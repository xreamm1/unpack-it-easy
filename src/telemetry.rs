use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Instant};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Progress {
    pub phase: String,
    pub file: String,
    pub done: usize,
    pub total: usize,
}

impl Progress {
    pub fn counter(&self, english: bool) -> String {
        if self.phase == "model download" {
            let mib = 1024.0 * 1024.0;
            let percent = if self.total == 0 {
                0.0
            } else {
                self.done.min(self.total) as f64 / self.total as f64 * 100.0
            };
            format!(
                "{:.1} / {:.1} MiB ({percent:.0}%)",
                self.done as f64 / mib,
                self.total as f64 / mib
            )
        } else {
            format!(
                "{} / {} {}",
                self.done,
                self.total,
                if english {
                    "objects"
                } else {
                    "\u{43e}\u{431}\u{44a}\u{435}\u{43a}\u{442}\u{43e}\u{432}"
                }
            )
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Problem {
    pub file: PathBuf,
    pub symbol: String,
    pub line: usize,
    pub message: String,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    pub seconds: [Option<f64>; 7],
    pub progress: Option<Progress>,
    pub problems: Vec<Problem>,
    pub active_file: Option<PathBuf>,
    pub search: String,
    pub tab: usize,
    pub renames: Vec<crate::rename::Change>,
}

#[derive(Default)]
pub struct StageClock {
    active: Option<(usize, Instant)>,
}

impl StageClock {
    pub fn begin(&mut self, index: usize, at: Instant, session: &mut Session) {
        self.finish(at, session);
        self.active = Some((index, at));
    }
    pub fn finish(&mut self, at: Instant, session: &mut Session) {
        if let Some((index, start)) = self.active.take() {
            if let Some(slot) = session.seconds.get_mut(index) {
                *slot =
                    Some(slot.unwrap_or(0.0) + at.saturating_duration_since(start).as_secs_f64());
            }
        }
    }
    pub fn elapsed(&self, index: usize, session: &Session) -> Option<f64> {
        let saved = *session.seconds.get(index)?;
        match self.active {
            Some((active, start)) if active == index => {
                Some(saved.unwrap_or(0.0) + start.elapsed().as_secs_f64())
            }
            _ => saved,
        }
    }
}

pub fn is_base(path: &std::path::Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("uie") || e.eq_ignore_ascii_case("toker"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_units_distinguish_download_bytes_from_objects() {
        let mut progress = Progress {
            phase: "model download".into(),
            done: 1048576,
            total: 2097152,
            ..Default::default()
        };
        assert_eq!(progress.counter(true), "1.0 / 2.0 MiB (50%)");
        progress.phase = "decompilation".into();
        progress.done = 3;
        progress.total = 10;
        assert_eq!(progress.counter(true), "3 / 10 objects");
        progress.phase = "model download".into();
        progress.total = 0;
        assert!(!progress.counter(true).contains("NaN"));
    }
    #[test]
    fn timings_measure_only_visited_stages_and_accumulate() {
        let start = Instant::now();
        let mut clock = StageClock::default();
        let mut session = Session::default();
        clock.begin(0, start, &mut session);
        clock.begin(
            4,
            start + std::time::Duration::from_millis(20),
            &mut session,
        );
        clock.finish(start + std::time::Duration::from_millis(1420), &mut session);
        assert_eq!(session.seconds[0], Some(0.02));
        assert_eq!(session.seconds[4], Some(1.4));
        assert_eq!(session.seconds[1], None);
    }
}
