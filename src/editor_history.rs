use std::collections::VecDeque;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_EDITS: usize = 512;

struct Edit {
    at: usize,
    before: String,
    after: String,
}
impl Edit {
    fn bytes(&self) -> usize {
        self.before.len() + self.after.len()
    }
}

#[derive(Default)]
pub struct History {
    undo: VecDeque<Edit>,
    redo: Vec<Edit>,
    bytes: usize,
}
impl History {
    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }
    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }
    pub fn record(&mut self, before: &str, after: &str) {
        if before == after {
            return;
        }
        self.redo.clear();
        let mut prefix = before
            .bytes()
            .zip(after.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        while !before.is_char_boundary(prefix) || !after.is_char_boundary(prefix) {
            prefix -= 1;
        }
        let mut suffix = before[prefix..]
            .bytes()
            .rev()
            .zip(after[prefix..].bytes().rev())
            .take_while(|(a, b)| a == b)
            .count();
        while !before.is_char_boundary(before.len() - suffix)
            || !after.is_char_boundary(after.len() - suffix)
        {
            suffix -= 1;
        }
        let edit = Edit {
            at: prefix,
            before: before[prefix..before.len() - suffix].into(),
            after: after[prefix..after.len() - suffix].into(),
        };
        self.push(edit);
    }
    pub fn record_range(&mut self, at: usize, before: &str, after: &str) {
        if before == after {
            return;
        }
        self.redo.clear();
        self.push(Edit {
            at,
            before: before.into(),
            after: after.into(),
        });
    }
    fn push(&mut self, edit: Edit) {
        if edit.bytes() > MAX_BYTES {
            self.undo.clear();
            self.bytes = 0;
            return;
        }
        self.bytes += edit.bytes();
        self.undo.push_back(edit);
        while self.bytes > MAX_BYTES || self.undo.len() > MAX_EDITS {
            self.bytes -= self.undo.pop_front().unwrap().bytes();
        }
    }
    pub fn undo(&mut self, text: &mut String) -> bool {
        let Some(edit) = self.undo.pop_back() else {
            return false;
        };
        self.bytes -= edit.bytes();
        if text.get(edit.at..edit.at + edit.after.len()) != Some(edit.after.as_str()) {
            self.undo.clear();
            self.redo.clear();
            self.bytes = 0;
            return false;
        }
        text.replace_range(edit.at..edit.at + edit.after.len(), &edit.before);
        self.redo.push(edit);
        true
    }
    pub fn redo(&mut self, text: &mut String) -> bool {
        let Some(edit) = self.redo.pop() else {
            return false;
        };
        if text.get(edit.at..edit.at + edit.before.len()) != Some(edit.before.as_str()) {
            self.undo.clear();
            self.redo.clear();
            self.bytes = 0;
            return false;
        }
        text.replace_range(edit.at..edit.at + edit.before.len(), &edit.after);
        self.bytes += edit.bytes();
        self.undo.push_back(edit);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_multiline_and_branching() {
        let mut history = History::default();
        let mut text = String::from("def пример():\n    return 1\n");
        let changed = text.replace("1", "42\n# строка");
        history.record(&text, &changed);
        text = changed.clone();
        assert!(history.undo(&mut text));
        assert!(text.ends_with("return 1\n"));
        assert!(history.redo(&mut text));
        assert_eq!(text, changed);
        assert!(history.undo(&mut text));
        history.record(&text, "другое");
        assert!(!history.can_redo());
    }
    #[test]
    fn divergent_source_never_gets_patched() {
        let mut history = History::default();
        history.record("abc", "axc");
        let mut text = "abc".to_string();
        assert!(!history.undo(&mut text));
        assert_eq!(text, "abc");
    }
    #[test]
    fn bounded_history_drops_oldest_edits() {
        let mut history = History::default();
        let mut text = String::new();
        for _ in 0..600 {
            let next = format!("{text}x");
            history.record(&text, &next);
            text = next;
        }
        let mut count = 0;
        while history.undo(&mut text) {
            count += 1;
        }
        assert_eq!(count, MAX_EDITS);
    }
}
