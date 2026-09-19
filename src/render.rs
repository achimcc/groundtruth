//! The Prometheus text format.

use std::fmt::Write;

use crate::config::Check;
use crate::outcome::Outcome;

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn labels(check: &Check) -> String {
    format!(
        "check=\"{}\",probe=\"{}\"",
        escape(&check.name),
        check.probe.kind()
    )
}

fn number(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

pub fn render(results: &[(Check, Outcome)], now: u64, duration: f64) -> String {
    let mut out = String::new();

    out.push_str(
        "# HELP groundtruth_ok The verdict of a check: 1 as expected, 0 not, or not measurable.\n",
    );
    out.push_str("# TYPE groundtruth_ok gauge\n");
    for (check, outcome) in results {
        // A probe that judges and could not measure is not fine: 0. One that
        // had nothing to judge stays silent.
        let verdict = match (outcome.success, outcome.ok) {
            (false, _) if check.probe.judges() => Some(false),
            (true, ok) => ok,
            _ => None,
        };
        if let Some(ok) = verdict {
            let _ = writeln!(out, "groundtruth_ok{{{}}} {}", labels(check), u8::from(ok));
        }
    }

    out.push_str("# HELP groundtruth_value The measurement behind a check.\n");
    out.push_str("# TYPE groundtruth_value gauge\n");
    for (check, outcome) in results {
        for (item, value) in &outcome.values {
            let _ = writeln!(
                out,
                "groundtruth_value{{{},item=\"{}\"}} {}",
                labels(check),
                escape(item),
                number(*value)
            );
        }
    }

    out.push_str("# HELP groundtruth_probe_success Whether the probe could measure at all.\n");
    out.push_str("# TYPE groundtruth_probe_success gauge\n");
    for (check, outcome) in results {
        let _ = writeln!(
            out,
            "groundtruth_probe_success{{{}}} {}",
            labels(check),
            u8::from(outcome.success)
        );
    }

    out.push_str("# HELP groundtruth_last_run_timestamp_seconds When the checks last ran.\n");
    out.push_str("# TYPE groundtruth_last_run_timestamp_seconds gauge\n");
    let _ = writeln!(out, "groundtruth_last_run_timestamp_seconds {now}");
    out.push_str("# HELP groundtruth_run_duration_seconds How long the run took.\n");
    out.push_str("# TYPE groundtruth_run_duration_seconds gauge\n");
    let _ = writeln!(out, "groundtruth_run_duration_seconds {duration:.3}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Probe;

    fn check(name: &str, probe: Probe) -> Check {
        Check {
            name: name.into(),
            probe,
        }
    }

    fn sysctl() -> Probe {
        Probe::Sysctl {
            key: "k".into(),
            expect: "1".into(),
        }
    }

    fn counter() -> Probe {
        Probe::NftCounter {
            family: "inet".into(),
            table: "t".into(),
            counters: vec![],
        }
    }

    #[test]
    fn verdict_value_and_success() {
        let results = vec![(
            check("a", sysctl()),
            Outcome::judged(true, vec![("value".into(), 1.0)], None),
        )];
        let text = render(&results, 100, 0.25);
        assert!(text.contains("groundtruth_ok{check=\"a\",probe=\"sysctl\"} 1\n"));
        assert!(
            text.contains("groundtruth_value{check=\"a\",probe=\"sysctl\",item=\"value\"} 1\n")
        );
        assert!(text.contains("groundtruth_probe_success{check=\"a\",probe=\"sysctl\"} 1\n"));
        assert!(text.contains("groundtruth_last_run_timestamp_seconds 100\n"));
        assert_eq!(text.matches("# TYPE groundtruth_ok ").count(), 1);
    }

    #[test]
    fn a_probe_that_could_not_measure_is_not_ok() {
        let results = vec![(check("a", sysctl()), Outcome::failed("no such key"))];
        let text = render(&results, 0, 0.0);
        assert!(text.contains("groundtruth_ok{check=\"a\",probe=\"sysctl\"} 0\n"));
        assert!(text.contains("groundtruth_probe_success{check=\"a\",probe=\"sysctl\"} 0\n"));
    }

    #[test]
    fn a_probe_without_a_verdict_never_shows_one() {
        let ok = Outcome {
            success: true,
            ok: None,
            values: vec![("c".into(), 7.0)],
            note: None,
        };
        let results = vec![
            (check("c", counter()), ok),
            (check("d", counter()), Outcome::failed("x")),
        ];
        let text = render(&results, 0, 0.0);
        assert!(!text.contains("groundtruth_ok{"));
        assert!(text.contains("groundtruth_probe_success{check=\"d\",probe=\"nft_counter\"} 0\n"));
    }

    #[test]
    fn labels_are_escaped() {
        let results = vec![(
            check("a\"b\\c", sysctl()),
            Outcome::judged(true, vec![], None),
        )];
        assert!(render(&results, 0, 0.0).contains("check=\"a\\\"b\\\\c\""));
    }
}
