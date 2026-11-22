//! The live progress model: installer events folded into the ten grouped rows, the log and the
//! final state. Pure, so the progress screen is tested without a UI.

use std::collections::HashMap;

use crate::backend::{GROUPS, InstallEvent, InstallFailure, InstallOutcome, StageState, group_of};

/// State of one grouped row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowState {
    /// Not started.
    Pending,
    /// A stage of the row runs.
    Running,
    /// Every stage of the row is done or skipped.
    Done,
    /// A stage of the row failed.
    Failed,
    /// Recorded for later (backups in Phase 1).
    Deferred,
}

/// One row as shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Row title.
    pub title: &'static str,
    /// The stage ids it covers.
    pub ids: String,
    /// State.
    pub state: RowState,
    /// Total time of the finished stages in milliseconds.
    pub ms: u64,
    /// "Step 5 of 12: Installing apps".
    pub detail: String,
    /// -2 no bar, -1 unknown, else 0..=100.
    pub percent: i32,
}

/// The run as a whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Run {
    /// Running.
    Running,
    /// The installer failed.
    Failed(InstallFailure),
    /// The SSH connection (or the setup connection) was lost.
    Lost {
        /// The last stage seen.
        stage: String,
    },
    /// Finished.
    Done(InstallOutcome),
}

/// Events folded into rows.
#[derive(Debug)]
pub struct Model {
    /// The ten rows.
    pub rows: Vec<Row>,
    /// The run state.
    pub run: Run,
    /// Image path text, once the installer said.
    pub image: Option<(bool, String)>,
    log: Vec<String>,
    seen: HashMap<String, StageState>,
    /// Stages that completed (done, skipped or deferred).
    finished: std::collections::HashSet<String>,
    started: std::time::Instant,
    clock: fn() -> String,
}

fn utc_clock() -> String {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    /// A fresh model: ten pending rows.
    pub fn new() -> Self {
        Self::with_clock(utc_clock)
    }

    /// With a fixed clock for log lines (tests).
    pub fn with_clock(clock: fn() -> String) -> Self {
        Self {
            rows: GROUPS
                .iter()
                .map(|g| Row {
                    title: g.title,
                    ids: g.stages.join(", "),
                    state: RowState::Pending,
                    ms: 0,
                    detail: String::new(),
                    percent: -2,
                })
                .collect(),
            run: Run::Running,
            image: None,
            log: Vec::new(),
            seen: HashMap::new(),
            finished: Default::default(),
            started: std::time::Instant::now(),
            clock,
        }
    }

    /// Resets for a retry: finished rows stay (the installer skips them), the failure goes.
    pub fn restart(&mut self) {
        self.run = Run::Running;
        for r in &mut self.rows {
            if r.state == RowState::Failed {
                r.state = RowState::Pending;
            }
        }
    }

    fn line(&mut self, text: String) {
        let t = (self.clock)();
        self.log.push(format!("{t} {text}"));
        if self.log.len() > 2000 {
            self.log.drain(..500);
        }
    }

    /// The log as one text.
    pub fn log_text(&self) -> String {
        self.log.join("\n")
    }

    /// Index of the row that is running, or the last finished one.
    pub fn current(&self) -> usize {
        self.rows
            .iter()
            .position(|r| matches!(r.state, RowState::Running | RowState::Failed))
            .or_else(|| {
                self.rows
                    .iter()
                    .rposition(|r| matches!(r.state, RowState::Done | RowState::Deferred))
                    .map(|i| (i + 1).min(self.rows.len() - 1))
            })
            .unwrap_or(0)
    }

    /// "Stage 6 of 10".
    pub fn stage_text(&self) -> String {
        format!("Stage {} of {}", self.current() + 1, self.rows.len())
    }

    fn refresh(&mut self, g: usize) {
        let stages = GROUPS[g].stages;
        let done = stages.iter().all(|s| self.finished.contains(*s));
        let deferred = stages
            .iter()
            .all(|s| self.seen.get(*s) == Some(&StageState::Deferred));
        let started = stages.iter().any(|s| self.seen.contains_key(*s));
        let row = &mut self.rows[g];
        if row.state == RowState::Failed {
            return;
        }
        row.state = if deferred {
            RowState::Deferred
        } else if done {
            RowState::Done
        } else if started {
            RowState::Running
        } else {
            RowState::Pending
        };
        if row.state != RowState::Running {
            row.percent = -2;
            if row.state == RowState::Done {
                row.detail.clear();
            }
        }
    }

    /// Folds one installer event in.
    pub fn apply(&mut self, e: InstallEvent) {
        match e {
            InstallEvent::Stage { id, state, ms } => {
                let g = group_of(&id);
                self.seen.insert(id.clone(), state);
                match state {
                    StageState::Start => {
                        self.line(format!("stage {id} .......... start"));
                        if let Some(g) = g {
                            self.rows[g].percent = -1;
                        }
                    }
                    StageState::Done | StageState::Skipped | StageState::Deferred => {
                        self.finished.insert(id.clone());
                        let word = match state {
                            StageState::Skipped => "skipped".to_owned(),
                            StageState::Deferred => "set up later".to_owned(),
                            _ => ms.map_or("done".to_owned(), |m| {
                                format!("done ({})", duration_text(m))
                            }),
                        };
                        self.line(format!("stage {id} .......... {word}"));
                        if let (Some(g), Some(m)) = (g, ms) {
                            self.rows[g].ms += m;
                        }
                    }
                }
                if let Some(g) = g {
                    self.refresh(g);
                }
            }
            InstallEvent::Step {
                stage,
                index,
                total,
                text,
                percent,
            } => {
                self.line(format!("step {index}/{total} {text}"));
                if let Some(g) = group_of(&stage) {
                    let row = &mut self.rows[g];
                    row.detail = format!("Step {index} of {total}: {text}");
                    row.percent = percent.map_or(-1, i32::from);
                    if row.state == RowState::Pending {
                        row.state = RowState::Running;
                    }
                }
            }
            InstallEvent::Warn(w) => self.line(format!("warn {w}")),
            InstallEvent::Log(l) => self.line(l),
            InstallEvent::ImagePath { prebuilt, reason } => {
                self.image = Some((prebuilt, reason));
            }
            InstallEvent::ConnectionLost { stage } => {
                self.line(format!("connection lost at stage {stage}"));
                self.run = Run::Lost { stage };
            }
            InstallEvent::Failed(f) => {
                self.line(format!(
                    "stage {} failed: {} ({}{})",
                    f.stage,
                    f.message,
                    f.code,
                    if f.retryable { ", retryable" } else { "" }
                ));
                if let Some(g) = group_of(&f.stage) {
                    self.rows[g].state = RowState::Failed;
                    self.rows[g].percent = -2;
                }
                self.run = Run::Failed(f);
            }
            InstallEvent::Finished(o) => {
                self.line("install finished".into());
                for g in 0..self.rows.len() {
                    if self.rows[g].state != RowState::Deferred {
                        self.rows[g].state = RowState::Done;
                        self.rows[g].percent = -2;
                        self.rows[g].detail.clear();
                    }
                }
                self.run = Run::Done(o);
            }
        }
    }

    /// Seconds since the model was created.
    pub fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

/// "1.2 s", "38 s", "1 min 4 s".
pub fn duration_text(ms: u64) -> String {
    if ms < 10_000 {
        return format!("{:.1} s", ms as f64 / 1000.0);
    }
    let s = (ms + 500) / 1000;
    if s < 60 {
        format!("{s} s")
    } else {
        format!("{} min {} s", s / 60, s % 60)
    }
}

/// "6 minutes 14 seconds".
pub fn long_duration(secs: u64) -> String {
    let (m, s) = (secs / 60, secs % 60);
    let p = |n: u64, w: &str| format!("{n} {w}{}", if n == 1 { "" } else { "s" });
    if m == 0 {
        p(s, "second")
    } else {
        format!("{} {}", p(m, "minute"), p(s, "second"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clk() -> String {
        "14:00:00".into()
    }

    fn stage(id: &str, s: StageState, ms: Option<u64>) -> InstallEvent {
        InstallEvent::Stage {
            id: id.into(),
            state: s,
            ms,
        }
    }

    #[test]
    fn rows_follow_the_events_and_a_group_is_done_when_all_its_stages_are() {
        let mut m = Model::with_clock(clk);
        assert_eq!(m.rows.len(), 10);
        m.apply(stage("preflight", StageState::Start, None));
        assert_eq!(m.rows[0].state, RowState::Running);
        m.apply(stage("preflight", StageState::Done, Some(1200)));
        assert_eq!(m.rows[0].state, RowState::Done);
        assert_eq!(m.rows[0].ms, 1200);
        // "Install the agent" covers five stages
        m.apply(stage("release", StageState::Start, None));
        m.apply(stage("release", StageState::Done, Some(1000)));
        assert_eq!(
            m.rows[3].state,
            RowState::Running,
            "four stages still to do"
        );
        for id in ["system-files", "credentials", "config", "units"] {
            m.apply(stage(id, StageState::Start, None));
            m.apply(stage(id, StageState::Done, Some(1000)));
        }
        assert_eq!(m.rows[3].state, RowState::Done);
        assert_eq!(m.rows[3].ms, 5000);
    }

    #[test]
    fn steps_without_a_percentage_show_an_indeterminate_bar() {
        let mut m = Model::with_clock(clk);
        m.apply(stage("desktop", StageState::Start, None));
        m.apply(InstallEvent::Step {
            stage: "desktop".into(),
            index: 5,
            total: 12,
            text: "Installing apps".into(),
            percent: None,
        });
        assert_eq!(m.rows[5].percent, -1);
        assert_eq!(m.rows[5].detail, "Step 5 of 12: Installing apps");
        m.apply(InstallEvent::Step {
            stage: "desktop".into(),
            index: 6,
            total: 12,
            text: "x".into(),
            percent: Some(61),
        });
        assert_eq!(m.rows[5].percent, 61);
        m.apply(stage("desktop", StageState::Done, Some(3000)));
        assert_eq!(m.rows[5].percent, -2);
        assert!(m.rows[5].detail.is_empty());
    }

    #[test]
    fn backups_stay_set_up_later() {
        let mut m = Model::with_clock(clk);
        m.apply(stage("backup", StageState::Deferred, None));
        assert_eq!(m.rows[7].state, RowState::Deferred);
        m.apply(InstallEvent::Finished(InstallOutcome {
            server_key_hex: "00".into(),
            addresses: vec![],
            port: 443,
            agent_version: "0.1.0".into(),
            image_path: String::new(),
            elapsed_secs: 1,
        }));
        assert_eq!(m.rows[7].state, RowState::Deferred);
        assert!(
            m.rows
                .iter()
                .enumerate()
                .all(|(i, r)| i == 7 || r.state == RowState::Done)
        );
        assert!(matches!(m.run, Run::Done(_)));
    }

    #[test]
    fn failure_marks_the_row_and_retry_clears_it() {
        let mut m = Model::with_clock(clk);
        m.apply(stage("preflight", StageState::Done, Some(10)));
        m.apply(stage("packages", StageState::Done, Some(10)));
        m.apply(stage("incus", StageState::Start, None));
        m.apply(InstallEvent::Failed(InstallFailure {
            stage: "incus".into(),
            code: "UNAVAILABLE".into(),
            message: "unreachable".into(),
            retryable: true,
        }));
        assert_eq!(m.rows[2].state, RowState::Failed);
        assert_eq!(m.stage_text(), "Stage 3 of 10");
        assert!(
            m.log_text()
                .contains("stage incus failed: unreachable (UNAVAILABLE, retryable)")
        );
        m.restart();
        assert_eq!(m.run, Run::Running);
        assert_eq!(m.rows[2].state, RowState::Pending);
        assert_eq!(m.rows[0].state, RowState::Done, "finished rows are kept");
    }

    #[test]
    fn connection_lost_keeps_the_stage() {
        let mut m = Model::with_clock(clk);
        m.apply(stage("desktop", StageState::Start, None));
        m.apply(InstallEvent::ConnectionLost {
            stage: "desktop".into(),
        });
        assert_eq!(
            m.run,
            Run::Lost {
                stage: "desktop".into()
            }
        );
        assert_eq!(m.rows[5].state, RowState::Running);
    }

    #[test]
    fn duration_formats() {
        assert_eq!(duration_text(1200), "1.2 s");
        assert_eq!(duration_text(38_000), "38 s");
        assert_eq!(duration_text(64_000), "1 min 4 s");
        assert_eq!(long_duration(374), "6 minutes 14 seconds");
        assert_eq!(long_duration(1), "1 second");
    }

    #[test]
    fn a_whole_scripted_install_finishes_cleanly() {
        use crate::backend::demo::{Scenario, install_script};
        let mut m = Model::with_clock(clk);
        for e in install_script(Scenario::Success, 443) {
            m.apply(e);
        }
        assert!(matches!(m.run, Run::Done(_)));
        assert!(m.image.is_some());
    }
}
