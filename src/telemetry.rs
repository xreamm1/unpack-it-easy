use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Instant};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Progress {
    pub phase: String,
    pub file: String,
    pub done: usize,
    pub total: usize,
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
