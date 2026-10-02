//! One pure function per probe: what the machine answered, and what that
//! means for the check.

mod firewall;
mod host;
mod network;

use std::net::IpAddr;

use serde_json::Value;

use crate::config::{Check, Probe};
use crate::exec::Runner;
use crate::outcome::Outcome;

pub fn run_check(check: &Check, runner: &dyn Runner) -> Outcome {
    match &check.probe {
        Probe::NftSet {
            family,
            table,
            set,
            min,
        } => firewall::nft_set(runner, family, table, set, *min),
        Probe::NftCounter {
            family,
            table,
            counters,
        } => firewall::nft_counter(runner, family, table, counters),
        Probe::IptablesDnatDuplicates {} => firewall::iptables_dnat_duplicates(runner),
        Probe::Sysctl { key, expect } => host::sysctl(runner, key, expect),
        Probe::ProxyNeigh { dev, expect } => network::proxy_neigh(runner, dev, expect),
        Probe::MachineAddr {
            machine,
            ifname,
            expect,
        } => network::machine_addr(runner, machine, ifname, expect),
        Probe::MachineCaps { machine, expect } => network::machine_caps(runner, machine, expect),
        Probe::BridgeIsolated { ports } => network::bridge_isolated(runner, ports),
    }
}

/// The JSON a tool printed, or the outcome that says why there is none.
fn json(runner: &dyn Runner, argv: &[&str]) -> Result<Value, Outcome> {
    let text = runner
        .run(argv)
        .map_err(|e| Outcome::failed(format!("{e:#}")))?;
    serde_json::from_str(&text)
        .map_err(|e| Outcome::failed(format!("{}: not JSON: {e}", argv.join(" "))))
}

/// Addresses compare by value, not by spelling: `fd00::0:1` is `fd00::1`.
fn same_address(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// `*` matches any run of characters; nothing else is special.
fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty();
    };
    for part in parts {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("vb-*", "vb-infra-01"));
        assert!(!glob("vb-*", "br-exp"));
        assert!(glob("*", "anything"));
        assert!(glob("a*c*e", "abcde"));
        assert!(!glob("a*c*e", "abcd"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
    }

    #[test]
    fn addresses_compare_by_value() {
        assert!(same_address("fd00::0:1", "fd00::1"));
        assert!(same_address("FD00::1", "fd00::1"));
        assert!(!same_address("fd00::1", "fd00::2"));
    }
}
