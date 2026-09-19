use crate::exec::Runner;
use crate::outcome::Outcome;

/// `net.ipv4.ip_forward` lives in `/proc/sys/net/ipv4/ip_forward`. An
/// interface name may hold a dot of its own (`eth0.20`): write such a key
/// with slashes and it is taken as it stands.
fn path(key: &str) -> String {
    if key.contains('/') {
        format!("/proc/sys/{}", key.trim_start_matches('/'))
    } else {
        format!("/proc/sys/{}", key.replace('.', "/"))
    }
}

fn normalised(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn sysctl(runner: &dyn Runner, key: &str, expect: &str) -> Outcome {
    // A key that cannot be read is the finding this probe exists for: the
    // interface it named was renamed, and the setting went with it.
    let found = match runner.read(&path(key)) {
        Ok(text) => normalised(&text),
        Err(e) => return Outcome::failed(format!("{e:#}")),
    };
    let ok = found == normalised(expect);
    let mut values = Vec::new();
    if let Ok(number) = found.parse::<f64>() {
        values.push(("value".to_string(), number));
    }
    Outcome::judged(
        ok,
        values,
        Some(format!("{key} = {found}, expected {expect}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeRunner;

    #[test]
    fn keys_become_paths() {
        assert_eq!(
            path("kernel.kptr_restrict"),
            "/proc/sys/kernel/kptr_restrict"
        );
        assert_eq!(
            path("net/ipv6/conf/eth0.20/use_tempaddr"),
            "/proc/sys/net/ipv6/conf/eth0.20/use_tempaddr"
        );
    }

    #[test]
    fn expected_other_and_gone() {
        let r = FakeRunner::default().file("/proc/sys/kernel/kptr_restrict", "1\n");
        let fine = sysctl(&r, "kernel.kptr_restrict", "1");
        assert_eq!(
            (fine.ok, fine.values.clone()),
            (Some(true), vec![("value".into(), 1.0)])
        );
        assert_eq!(sysctl(&r, "kernel.kptr_restrict", "2").ok, Some(false));
        // The interface was renamed: the key is gone.
        assert!(!sysctl(&r, "net.ipv6.conf.enp4s0.use_tempaddr", "0").success);
    }

    #[test]
    fn whitespace_does_not_matter() {
        let r =
            FakeRunner::default().file("/proc/sys/net/ipv4/tcp_rmem", "4096\t131072\t6291456\n");
        assert_eq!(
            sysctl(&r, "net.ipv4.tcp_rmem", "4096 131072 6291456").ok,
            Some(true)
        );
    }
}
