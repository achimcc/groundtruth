use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use lexopt::prelude::*;

use groundtruth::config::Config;
use groundtruth::exec::RealRunner;
use groundtruth::probes::run_check;
use groundtruth::render::render;

const HELP: &str = "\
groundtruth: measures the state that a unit's status only promises

USAGE:
  groundtruth --config FILE --output FILE     write the metrics, atomically
  groundtruth --config FILE --stdout          print them, with a note per check

Meant for a timer and the textfile collector of the node exporter. Exits 0
once the metrics are written, red checks included: red is a metric, not a
failed unit. Exits 1 if the configuration or the output fails, 2 on usage.
";

enum Target {
    File(PathBuf),
    Stdout,
}

fn parse() -> Result<(PathBuf, Target)> {
    let mut parser = lexopt::Parser::from_env();
    let (mut config, mut target) = (None, None);
    while let Some(arg) = parser.next()? {
        match arg {
            Long("help") | Short('h') => {
                print!("{HELP}");
                std::process::exit(0);
            }
            Long("version") | Short('V') => {
                println!("groundtruth {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            Long("config") => config = Some(PathBuf::from(parser.value()?)),
            Long("output") => target = Some(Target::File(PathBuf::from(parser.value()?))),
            Long("stdout") => target = Some(Target::Stdout),
            other => return Err(other.unexpected().into()),
        }
    }
    match (config, target) {
        (Some(c), Some(t)) => Ok((c, t)),
        _ => bail!("--config and one of --output, --stdout are required, see --help"),
    }
}

/// The collector reads at any moment, in the middle of a write as well. It
/// must never see half a file: write next to the target, then rename.
fn write_atomically(path: &Path, text: &str) -> Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    let name = path.file_name().context("the output needs a file name")?;
    let tmp = dir.unwrap_or(Path::new(".")).join(format!(
        ".{}.{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("cannot write {}", path.display()))
}

fn real_main() -> Result<ExitCode> {
    let (config, target) = match parse() {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("groundtruth: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    let cfg = Config::load(&config)?;
    let runner = RealRunner {
        timeout: Duration::from_secs(10),
    };
    let begun = Instant::now();
    let results: Vec<_> = cfg
        .checks
        .iter()
        .map(|check| (check.clone(), run_check(check, &runner)))
        .collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let text = render(&results, now, begun.elapsed().as_secs_f64());
    match target {
        Target::File(path) => write_atomically(&path, &text)?,
        Target::Stdout => {
            print!("{text}");
            for (check, outcome) in &results {
                let verdict = match (outcome.success, outcome.ok) {
                    (false, _) => "CANNOT MEASURE",
                    (true, Some(true)) => "ok",
                    (true, Some(false)) => "NOT AS EXPECTED",
                    (true, None) => "-",
                };
                let note = outcome.note.as_deref().unwrap_or("");
                eprintln!("{:<16} {:<28} {note}", verdict, check.name);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("groundtruth: {e:#}");
            ExitCode::from(1)
        }
    }
}
