//! The outside world: commands and files. Behind a trait, so that every
//! probe can be tested against what a real machine once answered.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

pub trait Runner {
    /// The standard output of a command that succeeded.
    fn run(&self, argv: &[&str]) -> Result<String>;
    fn read(&self, path: &str) -> Result<String>;
}

pub struct RealRunner {
    /// A hanging `nft` must not pile up timer runs.
    pub timeout: Duration,
}

impl Runner for RealRunner {
    fn run(&self, argv: &[&str]) -> Result<String> {
        let mut child = Command::new(argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot start {}", argv[0]))?;
        // Read in threads: a child that fills a pipe nobody reads never ends.
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            s
        });
        let err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        });
        let begun = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if begun.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{} did not finish within {:?}", argv[0], self.timeout);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = out.join().unwrap_or_default();
        let err = err.join().unwrap_or_default();
        if !status.success() {
            let first = err.lines().next().unwrap_or("").trim();
            bail!("{} failed ({status}): {first}", argv.join(" "));
        }
        Ok(out)
    }

    fn read(&self, path: &str) -> Result<String> {
        std::fs::read_to_string(path).with_context(|| format!("cannot read {path}"))
    }
}

/// Answers from a table, for tests. A command or file that is not in the
/// table fails, the way a missing object does on a real machine.
#[derive(Default)]
pub struct FakeRunner {
    pub commands: Vec<(String, String)>,
    pub files: Vec<(String, String)>,
}

impl FakeRunner {
    pub fn command(mut self, argv: &str, answer: &str) -> Self {
        self.commands.push((argv.to_string(), answer.to_string()));
        self
    }

    pub fn file(mut self, path: &str, content: &str) -> Self {
        self.files.push((path.to_string(), content.to_string()));
        self
    }
}

impl Runner for FakeRunner {
    fn run(&self, argv: &[&str]) -> Result<String> {
        let line = argv.join(" ");
        self.commands
            .iter()
            .find(|(k, _)| *k == line)
            .map(|(_, v)| v.clone())
            .with_context(|| format!("{line} failed: no such object"))
    }

    fn read(&self, path: &str) -> Result<String> {
        self.files
            .iter()
            .find(|(k, _)| k == path)
            .map(|(_, v)| v.clone())
            .with_context(|| format!("cannot read {path}"))
    }
}
