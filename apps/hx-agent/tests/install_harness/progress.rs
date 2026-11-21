//! A parser for the installer's JSON Lines progress (design C3) and a runner for one
//! `install.sh` invocation inside the L1 container. This is the harness side of what the 1G app
//! will do over SSH: write the C2 frames to stdin, read C3 lines from stdout, take the exit code.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Everything one run produced.
#[derive(Debug, Default, Clone)]
pub struct RunOut {
    pub exit: i32,
    /// stdout lines that parsed as JSON objects.
    pub lines: Vec<Value>,
    /// stdout lines that did not (the contract says there must be none).
    pub nonjson: Vec<String>,
    pub stderr: String,
    pub wall: Duration,
}

impl RunOut {
    /// `(id, state, ms)` of every `stage` line, in order.
    pub fn stages(&self) -> Vec<(String, String, u64)> {
        self.lines
            .iter()
            .filter(|l| l["t"] == "stage")
            .map(|l| {
                (
                    l["id"].as_str().unwrap_or_default().to_owned(),
                    l["state"].as_str().unwrap_or_default().to_owned(),
                    l["ms"].as_u64().unwrap_or(0),
                )
            })
            .collect()
    }

    /// The last state a stage reached in this run (`done`, `skip`, `fail`, ...).
    pub fn state_of(&self, id: &str) -> Option<String> {
        self.stages()
            .into_iter()
            .rev()
            .find(|(i, s, _)| i == id && s != "start")
            .map(|(_, s, _)| s)
    }

    /// Milliseconds the stage took when it finished `done` in this run.
    pub fn ms_of(&self, id: &str) -> Option<u64> {
        self.stages()
            .into_iter()
            .find(|(i, s, _)| i == id && s == "done")
            .map(|(_, _, ms)| ms)
    }

    /// The final `result` line.
    pub fn result(&self) -> Option<&Value> {
        self.lines.iter().rev().find(|l| l["t"] == "result")
    }

    /// Every `warn` line message.
    pub fn warnings(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter(|l| l["t"] == "warn")
            .map(|l| l["message"].as_str().unwrap_or_default().to_owned())
            .collect()
    }
}

/// Runs `argv` in `instance` through `incus exec`, writing `stdin` and closing it, and parses
/// stdout as JSON Lines. `on_line` sees every parsed line as it arrives (used to start a second
/// installer once the first one is inside a given stage).
pub fn run_in(
    instance: &str,
    argv: &[&str],
    stdin: &[u8],
    on_line: impl Fn(&Value) + Send + Sync + 'static,
) -> RunOut {
    let t0 = Instant::now();
    let mut c = Command::new("incus");
    c.args(["exec", instance, "--force-noninteractive", "--"])
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("spawn incus exec");
    let mut sin = child.stdin.take().expect("stdin");
    let out = child.stdout.take().expect("stdout");
    let err = child.stderr.take().expect("stderr");
    let data = stdin.to_vec();
    let w = std::thread::spawn(move || {
        // A failed write is the child having exited early; the exit code tells the story.
        let _ = sin.write_all(&data);
        drop(sin);
    });
    let e = std::thread::spawn(move || {
        let mut s = String::new();
        for l in BufReader::new(err).lines().map_while(Result::ok) {
            s.push_str(&l);
            s.push('\n');
        }
        s
    });
    let mut r = RunOut::default();
    for l in BufReader::new(out).lines().map_while(Result::ok) {
        match serde_json::from_str::<Value>(&l) {
            Ok(v) if v.is_object() => {
                on_line(&v);
                r.lines.push(v);
            }
            _ => r.nonjson.push(l),
        }
    }
    let st = child.wait().expect("wait");
    let _ = w.join();
    r.stderr = e.join().unwrap_or_default();
    r.exit = st.code().unwrap_or(-1);
    r.wall = t0.elapsed();
    r
}
