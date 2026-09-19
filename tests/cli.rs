//! The binary itself: what it writes, and how it ends.

use std::fs;
use std::process::Command;

fn groundtruth() -> Command {
    Command::new(env!("CARGO_BIN_EXE_groundtruth"))
}

// Readable on every Linux, by anyone: a sysctl that cannot be wrong.
const OS: &str =
    "[[check]]\nname = \"os\"\nprobe = \"sysctl\"\nkey = \"kernel.ostype\"\nexpect = \"Linux\"\n";
const GONE: &str = "[[check]]\nname = \"gone\"\nprobe = \"sysctl\"\nkey = \"kernel.no_such_key_here\"\nexpect = \"1\"\n";

#[test]
fn a_green_and_an_unmeasurable_check_side_by_side() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.toml");
    fs::write(&config, format!("{OS}{GONE}")).unwrap();
    let out = groundtruth()
        .args(["--config", config.to_str().unwrap(), "--stdout"])
        .output()
        .unwrap();
    // Red is a metric, not a failed unit.
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("groundtruth_ok{check=\"os\",probe=\"sysctl\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("groundtruth_ok{check=\"gone\",probe=\"sysctl\"} 0\n"),
        "{text}"
    );
    assert!(text.contains("groundtruth_probe_success{check=\"gone\",probe=\"sysctl\"} 0\n"));
    let notes = String::from_utf8(out.stderr).unwrap();
    assert!(notes.contains("CANNOT MEASURE"), "{notes}");
}

#[test]
fn the_file_appears_whole_and_nothing_is_left_beside_it() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.toml");
    let output = dir.path().join("out/groundtruth.prom");
    fs::create_dir(dir.path().join("out")).unwrap();
    fs::write(&config, OS).unwrap();
    let status = groundtruth()
        .args(["--config", config.to_str().unwrap()])
        .args(["--output", output.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let text = fs::read_to_string(&output).unwrap();
    assert!(text.ends_with('\n') && text.contains("groundtruth_last_run_timestamp_seconds "));
    let names: Vec<_> = fs::read_dir(dir.path().join("out"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["groundtruth.prom"]);
}

#[test]
fn a_broken_configuration_is_1_and_wrong_usage_is_2() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.toml");
    fs::write(&config, "[[check]]\nname = \"a\"\nprobe = \"nope\"\n").unwrap();
    let broken = groundtruth()
        .args(["--config", config.to_str().unwrap(), "--stdout"])
        .status()
        .unwrap();
    assert_eq!(broken.code(), Some(1));
    assert_eq!(groundtruth().status().unwrap().code(), Some(2));
    let nowhere = groundtruth()
        .args(["--config", "/no/such/file", "--stdout"])
        .status()
        .unwrap();
    assert_eq!(nowhere.code(), Some(1));
}

#[test]
fn a_directory_that_cannot_be_written_is_1() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.toml");
    fs::write(&config, OS).unwrap();
    let status = groundtruth()
        .args(["--config", config.to_str().unwrap()])
        .args(["--output", "/no/such/dir/groundtruth.prom"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}
