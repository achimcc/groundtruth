use serde_json::Value;

use super::{glob, json, same_address};
use crate::exec::Runner;
use crate::outcome::Outcome;

pub fn proxy_neigh(runner: &dyn Runner, dev: &str, expect: &[String]) -> Outcome {
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

pub fn machine_addr(
    runner: &dyn Runner,
    machine: &str,
    ifname: &str,
    expect: &[String],
) -> Outcome {
    let shown = runner.run(&["machinectl", "show", machine, "-p", "Leader", "-p", "State"]);
    let Ok(shown) = shown else {
        // Unknown to machined: it does not run. Whether it SHOULD is not
        // this probe's business. But a machinectl that answers nothing at
        // all would make every machine look stopped, so ask it once more.
        return match runner.run(&["machinectl", "list", "--no-legend"]) {
            Ok(_) => Outcome {
                success: true,
                ok: None,
                values: vec![("running".into(), 0.0)],
                note: Some(format!("{machine} is not running")),
            },
            Err(e) => Outcome::failed(format!("{e:#}")),
        };
    };
    let Some(leader) = property(&shown, "Leader").filter(|l| *l != "0") else {
        return Outcome::failed(format!("machinectl names no leader for {machine}"));
    };
    let argv = [
        "nsenter", "-t", leader, "-n", "ip", "-j", "addr", "show", "dev", ifname,
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

pub fn bridge_isolated(runner: &dyn Runner, ports: &str) -> Outcome {
    let doc = match json(runner, &["bridge", "-j", "-d", "link"]) {
        Ok(doc) => doc,
        Err(outcome) => return outcome,
    };
    let matching: Vec<&Value> = doc
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| l["ifname"].as_str().is_some_and(|n| glob(ports, n)))
        .collect();
    if matching.is_empty() {
        // A pattern that meets nothing measures nothing.
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
        let all = all_proxies();
        assert_eq!(proxy_neigh(&r, "br-exp", &all).ok, Some(true));

        let mut more = all.clone();
        more.push("fd00:dead::1".into());
        let o = proxy_neigh(&r, "br-exp", &more);
        assert_eq!((o.ok, o.values[0].1), (Some(false), 1.0));

        let o = proxy_neigh(&r, "br-exp", &all[1..]);
        assert_eq!((o.ok, o.values[1].1), (Some(false), 1.0));

        assert!(!proxy_neigh(&FakeRunner::default(), "br-gone", &all).success);
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
        let o = bridge_isolated(&r, "vb-*");
        assert_eq!((o.ok, o.values[0].1), (Some(true), 5.0));

        let mut doc: Value = serde_json::from_str(LINK).unwrap();
        doc[1]["isolated"] = Value::Bool(false);
        let r = FakeRunner::default().command("bridge -j -d link", &doc.to_string());
        let o = bridge_isolated(&r, "vb-*");
        assert_eq!(o.ok, Some(false));
        assert!(o.note.unwrap().contains("vb-torrent-01"));

        let r = FakeRunner::default().command("bridge -j -d link", LINK);
        assert!(!bridge_isolated(&r, "veth*").success);
    }
}
