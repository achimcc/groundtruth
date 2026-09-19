use std::collections::BTreeMap;

use serde_json::Value;

use super::json;
use crate::exec::Runner;
use crate::outcome::Outcome;

fn objects<'a>(doc: &'a Value, kind: &'a str) -> impl Iterator<Item = &'a Value> {
    doc["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(move |o| o.get(kind))
}

pub fn nft_set(runner: &dyn Runner, family: &str, table: &str, set: &str, min: u64) -> Outcome {
    let doc = match json(runner, &["nft", "-j", "list", "set", family, table, set]) {
        Ok(doc) => doc,
        Err(outcome) => return outcome,
    };
    let Some(found) = objects(&doc, "set").next() else {
        return Outcome::failed(format!("nft answered without the set {set}"));
    };
    // An empty set has no `elem` at all.
    let elements = found["elem"].as_array().map_or(0, Vec::len) as u64;
    Outcome::judged(
        elements >= min,
        vec![("elements".into(), elements as f64)],
        Some(format!("{elements} element(s), at least {min} expected")),
    )
}

pub fn nft_counter(runner: &dyn Runner, family: &str, table: &str, wanted: &[String]) -> Outcome {
    let argv = ["nft", "-j", "list", "counters", "table", family, table];
    let doc = match json(runner, &argv) {
        Ok(doc) => doc,
        Err(outcome) => return outcome,
    };
    let mut values = Vec::new();
    for counter in objects(&doc, "counter") {
        let Some(name) = counter["name"].as_str() else {
            continue;
        };
        if wanted.is_empty() || wanted.iter().any(|w| w == name) {
            values.push((name.to_string(), counter["packets"].as_f64().unwrap_or(0.0)));
        }
    }
    let missing: Vec<&String> = wanted
        .iter()
        .filter(|w| !values.iter().any(|(n, _)| n == *w))
        .collect();
    if !missing.is_empty() {
        return Outcome::failed(format!("no such counter in {family} {table}: {missing:?}"));
    }
    Outcome {
        success: true,
        ok: None,
        values,
        note: None,
    }
}

/// The value that follows a flag in one line of `iptables-save`.
fn flag<'a>(words: &[&'a str], name: &str) -> Option<&'a str> {
    words
        .iter()
        .position(|w| *w == name)
        .and_then(|i| words.get(i + 1))
        .copied()
}

pub fn iptables_dnat_duplicates(runner: &dyn Runner) -> Outcome {
    let text = match runner.run(&["iptables-save", "-t", "nat"]) {
        Ok(text) => text,
        Err(e) => return Outcome::failed(format!("{e:#}")),
    };
    if !text.contains("*nat") {
        return Outcome::failed("iptables-save answered without a nat table");
    }
    // (protocol, destination, port) -> where the rules send it.
    let mut rules: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();
    for line in text.lines().filter(|l| l.starts_with("-A ")) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let jump = flag(&words, "-j").unwrap_or("");
        // A rule without a port forwards everything; it has no twin to find.
        let Some(port) = flag(&words, "--dport") else {
            continue;
        };
        let proto = flag(&words, "-p").unwrap_or("all").to_string();
        if jump == "DNAT" {
            let dest = flag(&words, "-d").unwrap_or("any").to_string();
            let target = flag(&words, "--to-destination").unwrap_or("?").to_string();
            rules
                .entry((proto, dest, port.to_string()))
                .or_default()
                .push(target);
        } else if words[1].ends_with("HOSTPORT-DNAT") {
            // The switch in front of the DNAT rules: one jump per port into
            // the chain of a container. Of two jumps the first one wins.
            rules
                .entry((proto, format!("via {}", words[1]), port.to_string()))
                .or_default()
                .push(jump.to_string());
        }
    }
    let total: usize = rules.values().map(Vec::len).sum();
    let twice: Vec<String> = rules
        .iter()
        .filter(|(_, targets)| targets.len() > 1)
        .map(|((proto, dest, port), targets)| format!("{proto} {dest}:{port} -> {targets:?}"))
        .collect();
    Outcome::judged(
        twice.is_empty(),
        vec![
            ("duplicates".into(), twice.len() as f64),
            ("rules".into(), total as f64),
        ],
        (!twice.is_empty()).then(|| twice.join("; ")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeRunner;

    const SET: &str = include_str!("../../tests/fixtures/nft_set.json");
    const COUNTERS: &str = include_str!("../../tests/fixtures/nft_counters.json");
    const NAT: &str = include_str!("../../tests/fixtures/iptables_nat.txt");
    const LIST_SET: &str = "nft -j list set inet lan6 lanPraefixe";
    const LIST_COUNTERS: &str = "nft -j list counters table inet zonenkanten";

    #[test]
    fn a_filled_set_is_fine() {
        let r = FakeRunner::default().command(LIST_SET, SET);
        let o = nft_set(&r, "inet", "lan6", "lanPraefixe", 1);
        assert_eq!((o.success, o.ok), (true, Some(true)));
        assert_eq!(o.values, [("elements".to_string(), 2.0)]);
    }

    #[test]
    fn an_empty_set_is_the_open_barrier() {
        let mut doc: Value = serde_json::from_str(SET).unwrap();
        doc["nftables"][1]["set"]
            .as_object_mut()
            .unwrap()
            .remove("elem");
        let r = FakeRunner::default().command(LIST_SET, &doc.to_string());
        let o = nft_set(&r, "inet", "lan6", "lanPraefixe", 1);
        assert_eq!((o.success, o.ok), (true, Some(false)));
    }

    #[test]
    fn a_set_that_does_not_exist_cannot_be_measured() {
        let o = nft_set(&FakeRunner::default(), "inet", "lan6", "gone", 1);
        assert!(!o.success);
    }

    #[test]
    fn counters_are_values_without_a_verdict() {
        let r = FakeRunner::default().command(LIST_COUNTERS, COUNTERS);
        let all = nft_counter(&r, "inet", "zonenkanten", &[]);
        assert_eq!((all.success, all.ok), (true, None));
        assert_eq!(all.values.len(), 15);
        let one = nft_counter(&r, "inet", "zonenkanten", &["zonenkante_ungedeckt".into()]);
        assert_eq!(one.values.len(), 1);
        let none = nft_counter(&r, "inet", "zonenkanten", &["nope".into()]);
        assert!(!none.success);
    }

    #[test]
    fn the_real_nat_table_has_no_twins() {
        let r = FakeRunner::default().command("iptables-save -t nat", NAT);
        let o = iptables_dnat_duplicates(&r);
        assert_eq!((o.success, o.ok), (true, Some(true)));
        // Three DNAT rules and the three jumps that lead to them.
        assert_eq!(o.values[1], ("rules".to_string(), 6.0));
    }

    #[test]
    fn a_leftover_rule_for_the_same_port_is_found() {
        // What a failed teardown leaves: the dead container's rule, in front.
        let stale = "-A NETAVARK-DN-DEAD -d 127.0.0.1/32 -p tcp -m tcp --dport 3000 \
                     -j DNAT --to-destination 10.88.0.99:3000\n";
        let text = NAT.replacen("-A NETAVARK-DN", &format!("{stale}-A NETAVARK-DN"), 1);
        let has_3000 = NAT.contains("--dport 3000 ");
        assert!(has_3000, "the fixture forwards port 3000");
        let r = FakeRunner::default().command("iptables-save -t nat", &text);
        let o = iptables_dnat_duplicates(&r);
        assert_eq!(o.ok, Some(false));
        assert!(o.note.unwrap().contains("10.88.0.99:3000"));
    }

    #[test]
    fn a_leftover_jump_for_the_same_port_is_found() {
        let stale = "-A NETAVARK-HOSTPORT-DNAT -p tcp -m tcp --dport 3000 -j NETAVARK-DN-DEAD\n";
        let text = NAT.replacen(
            "-A NETAVARK-HOSTPORT-DNAT",
            &format!("{stale}-A NETAVARK-HOSTPORT-DNAT"),
            1,
        );
        let r = FakeRunner::default().command("iptables-save -t nat", &text);
        let o = iptables_dnat_duplicates(&r);
        assert_eq!(o.ok, Some(false));
        assert!(o.note.unwrap().contains("NETAVARK-DN-DEAD"));
    }

    #[test]
    fn no_nat_table_is_not_a_clean_bill() {
        let r = FakeRunner::default().command("iptables-save -t nat", "");
        assert!(!iptables_dnat_duplicates(&r).success);
    }
}
