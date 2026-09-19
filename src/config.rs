//! The checks: what to look at, and what to expect there.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "check")]
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub name: String,
    #[serde(flatten)]
    pub probe: Probe,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "probe", rename_all = "snake_case", deny_unknown_fields)]
pub enum Probe {
    /// A named nftables set holds at least `min` elements.
    NftSet {
        family: String,
        table: String,
        set: String,
        min: u64,
    },
    /// Named nftables counters, as raw values. No verdict.
    NftCounter {
        family: String,
        table: String,
        /// Empty: every counter of the table.
        #[serde(default)]
        counters: Vec<String>,
    },
    /// No two DNAT rules for the same protocol, destination and port.
    /// iptables takes the first one, which after a failed teardown is the
    /// one that points at a container long gone.
    IptablesDnatDuplicates {},
    /// A sysctl has the expected value.
    Sysctl { key: String, expect: String },
    /// The proxy neighbours of a device are exactly the expected ones.
    ProxyNeigh { dev: String, expect: Vec<Neighbour> },
    /// A running systemd machine holds its addresses, none of them failed
    /// or still tentative.
    MachineAddr {
        machine: String,
        ifname: String,
        expect: Vec<String>,
    },
    /// Every bridge port matching one of the patterns is isolated. `*` is
    /// the only wildcard.
    BridgeIsolated { ports: OneOrMany },
}

/// An address that must be a proxy neighbour — always, or for as long as a
/// systemd machine runs. Tied to a machine, it must be GONE while that
/// machine does not run: a proxy neighbour that outlives its guest answers
/// the guest's duplicate address detection when it comes back.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Neighbour {
    Always(String),
    WhileRunning(Tied),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tied {
    pub address: String,
    pub machine: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn as_slice(&self) -> &[String] {
        match self {
            OneOrMany::One(one) => std::slice::from_ref(one),
            OneOrMany::Many(many) => many,
        }
    }
}

impl Probe {
    pub fn kind(&self) -> &'static str {
        match self {
            Probe::NftSet { .. } => "nft_set",
            Probe::NftCounter { .. } => "nft_counter",
            Probe::IptablesDnatDuplicates { .. } => "iptables_dnat_duplicates",
            Probe::Sysctl { .. } => "sysctl",
            Probe::ProxyNeigh { .. } => "proxy_neigh",
            Probe::MachineAddr { .. } => "machine_addr",
            Probe::BridgeIsolated { .. } => "bridge_isolated",
        }
    }

    /// Does this probe pass a verdict, or only report values?
    pub fn judges(&self) -> bool {
        !matches!(self, Probe::NftCounter { .. })
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        let mut seen = BTreeSet::new();
        for check in &cfg.checks {
            if check.name.is_empty() {
                bail!("a check has an empty name");
            }
            if !seen.insert(check.name.as_str()) {
                bail!("the check name {:?} is used twice", check.name);
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("in {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_loads() {
        let cfg = Config::parse(include_str!("../groundtruth.example.toml")).unwrap();
        assert!(cfg.checks.len() >= 7);
        let kinds: BTreeSet<&str> = cfg.checks.iter().map(|c| c.probe.kind()).collect();
        assert_eq!(kinds.len(), 7, "the example shows every probe: {kinds:?}");
    }

    #[test]
    fn mistakes_are_errors() {
        let unknown_probe = "[[check]]\nname = \"a\"\nprobe = \"nope\"\n";
        assert!(Config::parse(unknown_probe).is_err());
        let unknown_key = "[[check]]\nname = \"a\"\nprobe = \"sysctl\"\nkey = \"k\"\nexpect = \"1\"\nexpcet = \"2\"\n";
        assert!(Config::parse(unknown_key).is_err());
        let twice = "[[check]]\nname = \"a\"\nprobe = \"sysctl\"\nkey = \"k\"\nexpect = \"1\"\n";
        let err = Config::parse(&format!("{twice}{twice}")).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
        assert!(Config::parse("chekc = 1\n").is_err());
    }
}
