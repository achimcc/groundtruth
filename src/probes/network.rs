use serde_json::Value;

use super::{glob, json, same_address};
use crate::config::{Neighbour, OneOrMany, Tied};
use crate::exec::Runner;
use crate::outcome::Outcome;

/// Does machined know the machine? `None`: machinectl itself does not answer.
fn runs(runner: &dyn Runner, machine: &str) -> Option<bool> {
    if runner
        .run(&["machinectl", "show", machine, "-p", "State"])
        .is_ok()
    {
        return Some(true);
    }
    runner
        .run(&["machinectl", "list", "--no-legend"])
        .ok()
        .map(|_| false)
}

pub fn proxy_neigh(runner: &dyn Runner, dev: &str, expect: &[Neighbour]) -> Outcome {
    // Whose machine does not run is not expected — and if it is there all
    // the same, it is the leftover this probe is after.
    let mut wanted: Vec<String> = Vec::new();
    for neighbour in expect {
        match neighbour {
            Neighbour::Always(address) => wanted.push(address.clone()),
            Neighbour::WhileRunning(Tied { address, machine }) => match runs(runner, machine) {
                Some(true) => wanted.push(address.clone()),
                Some(false) => {}
                None => return Outcome::failed("machinectl does not answer"),
            },
        }
    }
    let expect = &wanted;
    let doc = match json(
        runner,
        &["ip", "-j", "-6", "neigh", "show", "proxy", "dev", dev],
    ) {
        Ok(doc) => doc,
        Err(outcome) => return outcome,
    };
    let present: Vec<&str> = doc
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| n["dst"].as_str())
        .collect();
    let missing: Vec<&String> = expect
        .iter()
        .filter(|e| !present.iter().any(|p| same_address(p, e)))
        .collect();
    // One that nobody expects answers the duplicate address detection of a
    // guest that comes back, and the guest gives its address up.
    let unexpected: Vec<&&str> = present
        .iter()
        .filter(|p| !expect.iter().any(|e| same_address(p, e)))
        .collect();
    let ok = missing.is_empty() && unexpected.is_empty();
    Outcome::judged(
        ok,
        vec![
            ("missing".into(), missing.len() as f64),
            ("unexpected".into(), unexpected.len() as f64),
        ],
        (!ok).then(|| format!("missing {missing:?}, unexpected {unexpected:?}")),
    )
}

fn property<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
}

/// The leader PID of a running machine — or the outcome that ends the probe:
/// no verdict for a machine that does not run, a failure when machined
/// cannot be asked.
fn leader_of(runner: &dyn Runner, machine: &str) -> Result<String, Outcome> {
    let shown = runner.run(&["machinectl", "show", machine, "-p", "Leader", "-p", "State"]);
    let Ok(shown) = shown else {
        // Unknown to machined: it does not run. Whether it SHOULD is not
        // this probe's business. But a machinectl that answers nothing at
        // all would make every machine look stopped, so ask it once more.
        return Err(match runner.run(&["machinectl", "list", "--no-legend"]) {
            Ok(_) => Outcome {
                success: true,
                ok: None,
                values: vec![("running".into(), 0.0)],
                note: Some(format!("{machine} is not running")),
            },
            Err(e) => Outcome::failed(format!("{e:#}")),
        });
    };
    match property(&shown, "Leader").filter(|l| *l != "0") {
        Some(leader) => Ok(leader.to_string()),
        None => Err(Outcome::failed(format!(
            "machinectl names no leader for {machine}"
        ))),
    }
}

/// The capability bounding set of a running machine's leader is exactly the
/// expected mask. A bit too many is the finding this probe exists for: a
/// guest that was started before the cut, or by a unit that lost it. A bit
/// too few is reported as well — the declaration is then wrong, and a
/// service inside may be failing for it.
pub fn machine_caps(runner: &dyn Runner, machine: &str, expect: &str) -> Outcome {
    let Some(wanted) = mask(expect) else {
        return Outcome::failed(format!("expect {expect:?} is not a hexadecimal mask"));
    };
    let leader = match leader_of(runner, machine) {
        Ok(leader) => leader,
        Err(outcome) => return outcome,
    };
    let status = match runner.read(&format!("/proc/{leader}/status")) {
        Ok(text) => text,
        Err(e) => return Outcome::failed(format!("{e:#}")),
    };
    let found = status
        .lines()
        .find_map(|l| l.strip_prefix("CapBnd:"))
        .and_then(mask);
    let Some(found) = found else {
        return Outcome::failed(format!("/proc/{leader}/status names no CapBnd"));
    };
    let extra = found & !wanted;
    let missing = wanted & !found;
    let ok = extra == 0 && missing == 0;
    Outcome::judged(
        ok,
        vec![
            ("extra".into(), f64::from(extra.count_ones())),
            ("missing".into(), f64::from(missing.count_ones())),
        ],
        (!ok).then(|| {
            format!("{machine}: CapBnd {found:016x}, expected {wanted:016x} (extra {extra:x}, missing {missing:x})")
        }),
    )
}

fn mask(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

pub fn machine_addr(
    runner: &dyn Runner,
    machine: &str,
    ifname: &str,
    expect: &[String],
) -> Outcome {
    let leader = match leader_of(runner, machine) {
        Ok(leader) => leader,
        Err(outcome) => return outcome,
    };
    let argv = [
        "nsenter", "-t", &leader, "-n", "ip", "-j", "addr", "show", "dev", ifname,
    ];
    let doc = match json(runner, &argv) {
        Ok(doc) => doc,
        Err(outcome) => return outcome,
    };
    let addresses: Vec<&Value> = doc
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|link| link["addr_info"].as_array().into_iter().flatten())
        .collect();
    let flagged = |a: &Value, flag: &str| a[flag].as_bool().unwrap_or(false);
    let find = |wanted: &String| {
        addresses
            .iter()
            .find(|a| a["local"].as_str().is_some_and(|l| same_address(l, wanted)))
    };
    let missing = expect.iter().filter(|e| find(e).is_none()).count();
    let dadfailed = expect
        .iter()
        .filter(|e| find(e).is_some_and(|a| flagged(a, "dadfailed")))
        .count();
    let tentative = expect
        .iter()
        .filter(|e| find(e).is_some_and(|a| flagged(a, "tentative") && !flagged(a, "dadfailed")))
        .count();
    let ok = missing + dadfailed + tentative == 0;
    Outcome::judged(
        ok,
        vec![
            ("running".into(), 1.0),
            ("missing".into(), missing as f64),
            ("dadfailed".into(), dadfailed as f64),
            ("tentative".into(), tentative as f64),
        ],
        (!ok).then(|| {
            format!("{machine}/{ifname}: {missing} missing, {dadfailed} dadfailed, {tentative} tentative")
        }),
    )
}

pub fn bridge_isolated(runner: &dyn Runner, ports: &OneOrMany) -> Outcome {
    let ports = ports.as_slice();
    let doc = match json(runner, &["bridge", "-j", "-d", "link"]) {
        Ok(doc) => doc,
        Err(outcome) => return outcome,
    };
    let matching: Vec<&Value> = doc
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| {
            l["ifname"]
                .as_str()
                .is_some_and(|n| ports.iter().any(|p| glob(p, n)))
        })
        .collect();
    if matching.is_empty() {
        // Patterns that meet nothing at all measure nothing. A single name
        // that is missing is a guest that does not run, and no finding.
        return Outcome::failed(format!("no bridge port matches {ports:?}"));
    }
    let open: Vec<&str> = matching
        .iter()
        .filter(|l| l["isolated"].as_bool() != Some(true))
        .filter_map(|l| l["ifname"].as_str())
        .collect();
    Outcome::judged(
        open.is_empty(),
        vec![
            ("ports".into(), matching.len() as f64),
            ("not_isolated".into(), open.len() as f64),
        ],
        (!open.is_empty()).then(|| format!("not isolated: {open:?}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeRunner;

    const NEIGH: &str = include_str!("../../tests/fixtures/neigh_proxy.json");
    const ADDR: &str = include_str!("../../tests/fixtures/ip_addr_guest.json");
    const LINK: &str = include_str!("../../tests/fixtures/bridge_link.json");
    const SHOW: &str = "machinectl show infra-01 -p Leader -p State";
    const ENTER: &str = "nsenter -t 4242 -n ip -j addr show dev host0";

    fn all_proxies() -> Vec<String> {
        let doc: Value = serde_json::from_str(NEIGH).unwrap();
        doc.as_array()
            .unwrap()
            .iter()
            .map(|n| n["dst"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn proxies_as_expected_missing_and_left_over() {
        let cmd = "ip -j -6 neigh show proxy dev br-exp";
        let r = FakeRunner::default().command(cmd, NEIGH);
        let all: Vec<Neighbour> = all_proxies().into_iter().map(Neighbour::Always).collect();
        assert_eq!(proxy_neigh(&r, "br-exp", &all).ok, Some(true));

        let mut more = all.clone();
        more.push(Neighbour::Always("fd00:dead::1".into()));
        let o = proxy_neigh(&r, "br-exp", &more);
        assert_eq!((o.ok, o.values[0].1), (Some(false), 1.0));

        let o = proxy_neigh(&r, "br-exp", &all[1..]);
        assert_eq!((o.ok, o.values[1].1), (Some(false), 1.0));

        assert!(!proxy_neigh(&FakeRunner::default(), "br-gone", &all).success);
    }

    #[test]
    fn a_proxy_that_outlived_its_guest_is_the_finding() {
        let cmd = "ip -j -6 neigh show proxy dev br-exp";
        let addresses = all_proxies();
        let tied: Vec<Neighbour> = addresses
            .iter()
            .enumerate()
            .map(|(i, a)| {
                Neighbour::WhileRunning(Tied {
                    address: a.clone(),
                    machine: format!("guest-{i}"),
                })
            })
            .collect();
        let machines = |stopped: Option<usize>| {
            let mut r = FakeRunner::default()
                .command(cmd, NEIGH)
                .command("machinectl list --no-legend", "");
            for i in 0..addresses.len() {
                if Some(i) != stopped {
                    r = r.command(
                        &format!("machinectl show guest-{i} -p State"),
                        "State=running",
                    );
                }
            }
            r
        };
        assert_eq!(proxy_neigh(&machines(None), "br-exp", &tied).ok, Some(true));
        // guest-0 is stopped, its proxy neighbour is still there.
        let o = proxy_neigh(&machines(Some(0)), "br-exp", &tied);
        assert_eq!(o.ok, Some(false));
        assert_eq!(o.values[1], ("unexpected".to_string(), 1.0));
        // A machinectl that answers nothing must not read as "all stopped".
        let mute = FakeRunner::default().command(cmd, NEIGH);
        assert!(!proxy_neigh(&mute, "br-exp", &tied).success);
    }

    fn guest_address() -> String {
        let doc: Value = serde_json::from_str(ADDR).unwrap();
        doc[0]["addr_info"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["family"] == "inet6" && a["scope"] == "global")
            .expect("the fixture holds a global v6 address")["local"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn guest(addr_json: &str) -> FakeRunner {
        FakeRunner::default()
            .command(SHOW, "Leader=4242\nState=running\n")
            .command(ENTER, addr_json)
    }

    const STATUS: &str = "Name:\tsystemd\nCapInh:\t0000000000000000\nCapPrm:\t00000000a1ec15ff\nCapBnd:\t00000000a1ec15ff\nNoNewPrivs:\t0\n";

    fn caps(status: &str) -> FakeRunner {
        FakeRunner::default()
            .command(SHOW, "Leader=4242\nState=running\n")
            .file("/proc/4242/status", status)
    }

    #[test]
    fn a_guest_with_the_declared_bounding_set() {
        let o = machine_caps(&caps(STATUS), "infra-01", "a1ec15ff");
        assert_eq!((o.success, o.ok), (true, Some(true)));
        assert!(o.values.contains(&("extra".to_string(), 0.0)));
        // Spelled the way /proc spells it, or with a prefix: the same mask.
        assert_eq!(
            machine_caps(&caps(STATUS), "infra-01", "0x00000000a1ec15ff").ok,
            Some(true)
        );
    }

    #[test]
    fn a_guest_that_holds_a_capability_too_many() {
        // CAP_NET_RAW (bit 13) is back.
        let status = STATUS.replace("CapBnd:\t00000000a1ec15ff", "CapBnd:\t00000000a1ec35ff");
        let o = machine_caps(&caps(&status), "infra-01", "a1ec15ff");
        assert_eq!(o.ok, Some(false));
        assert!(o.values.contains(&("extra".to_string(), 1.0)));
        assert!(o.values.contains(&("missing".to_string(), 0.0)));
        assert!(o.note.unwrap().contains("extra 2000"));
    }

    #[test]
    fn a_guest_that_lacks_a_declared_capability() {
        // CAP_SYS_PTRACE (bit 19) is gone: systemd inside cannot set up
        // PrivateUsers any more.
        let status = STATUS.replace("CapBnd:\t00000000a1ec15ff", "CapBnd:\t00000000a1e415ff");
        let o = machine_caps(&caps(&status), "infra-01", "a1ec15ff");
        assert_eq!(o.ok, Some(false));
        assert!(o.values.contains(&("missing".to_string(), 1.0)));
    }

    #[test]
    fn capabilities_that_cannot_be_read_are_not_a_quiet_day() {
        // No status file: the leader died between the two questions.
        let gone = FakeRunner::default().command(SHOW, "Leader=4242\nState=running\n");
        assert!(!machine_caps(&gone, "infra-01", "a1ec15ff").success);
        // A status without the line, and a mask nobody can read.
        assert!(!machine_caps(&caps("Name:\tsystemd\n"), "infra-01", "a1ec15ff").success);
        assert!(!machine_caps(&caps(STATUS), "infra-01", "all of them").success);
    }

    #[test]
    fn a_stopped_guest_has_no_capabilities_to_judge() {
        let stopped = FakeRunner::default().command("machinectl list --no-legend", "");
        let o = machine_caps(&stopped, "infra-01", "a1ec15ff");
        assert_eq!((o.success, o.ok), (true, None));
    }

    #[test]
    fn a_guest_holds_its_address() {
        let o = machine_addr(&guest(ADDR), "infra-01", "host0", &[guest_address()]);
        assert_eq!((o.success, o.ok), (true, Some(true)));
    }

    #[test]
    fn a_guest_that_lost_the_duplicate_address_detection() {
        let mut doc: Value = serde_json::from_str(ADDR).unwrap();
        let wanted = guest_address();
        for a in doc[0]["addr_info"].as_array_mut().unwrap() {
            if a["local"] == wanted.as_str() {
                a["dadfailed"] = Value::Bool(true);
                a["tentative"] = Value::Bool(true);
            }
        }
        let o = machine_addr(&guest(&doc.to_string()), "infra-01", "host0", &[wanted]);
        assert_eq!(o.ok, Some(false));
        assert!(o.values.contains(&("dadfailed".to_string(), 1.0)));
        assert!(o.values.contains(&("tentative".to_string(), 0.0)));
    }

    #[test]
    fn an_address_that_is_not_there() {
        let o = machine_addr(&guest(ADDR), "infra-01", "host0", &["fd00:dead::1".into()]);
        assert_eq!(o.ok, Some(false));
    }

    #[test]
    fn a_stopped_machine_is_no_finding_but_a_dead_machinectl_is() {
        let listing = FakeRunner::default().command("machinectl list --no-legend", "");
        let o = machine_addr(&listing, "infra-01", "host0", &[guest_address()]);
        assert_eq!((o.success, o.ok), (true, None));
        assert_eq!(o.values, [("running".to_string(), 0.0)]);

        let o = machine_addr(
            &FakeRunner::default(),
            "infra-01",
            "host0",
            &[guest_address()],
        );
        assert!(!o.success);
    }

    #[test]
    fn isolated_ports_an_open_one_and_a_pattern_that_meets_nothing() {
        let r = FakeRunner::default().command("bridge -j -d link", LINK);
        let one = |p: &str| OneOrMany::One(p.to_string());
        let o = bridge_isolated(&r, &one("vb-*"));
        assert_eq!((o.ok, o.values[0].1), (Some(true), 5.0));
        // Exact names; the guest that does not run is simply not there.
        let named = OneOrMany::Many(vec!["vb-torrent-01".into(), "vb-stopped-01".into()]);
        let o = bridge_isolated(&r, &named);
        assert_eq!((o.ok, o.values[0].1), (Some(true), 1.0));

        let mut doc: Value = serde_json::from_str(LINK).unwrap();
        doc[1]["isolated"] = Value::Bool(false);
        let r = FakeRunner::default().command("bridge -j -d link", &doc.to_string());
        let o = bridge_isolated(&r, &one("vb-*"));
        assert_eq!(o.ok, Some(false));
        assert!(o.note.unwrap().contains("vb-torrent-01"));

        let r = FakeRunner::default().command("bridge -j -d link", LINK);
        assert!(!bridge_isolated(&r, &one("veth*")).success);
    }
}
