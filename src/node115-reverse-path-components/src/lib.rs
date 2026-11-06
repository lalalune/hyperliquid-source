//! Unix byte-path reverse components for the qualified fresh constructor.
//! This does not expose or accept the captured internal iterator ABI/states.
#![no_std]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component<'a> {
    Root,
    Current,
    Parent,
    Normal(&'a [u8]),
}
#[derive(Clone, Debug)]
pub struct Reverse<'a> {
    path: &'a [u8],
    end: usize,
    protected: usize,
    root: bool,
    current: bool,
    done: bool,
}
impl<'a> Reverse<'a> {
    pub fn new(path: &'a [u8]) -> Self {
        let root = path.first() == Some(&b'/');
        let current =
            !root && path.first() == Some(&b'.') && (path.len() == 1 || path.get(1) == Some(&b'/'));
        Self {
            path,
            end: path.len(),
            protected: usize::from(root || current),
            root,
            current,
            done: false,
        }
    }
    fn last(&self, end: usize) -> (usize, usize) {
        let start = self.path[self.protected..end]
            .iter()
            .rposition(|&b| b == b'/')
            .map_or(self.protected, |n| self.protected + n + 1);
        let consumed = end - start + usize::from(start > self.protected);
        (start, consumed)
    }
    pub fn remaining(&self) -> &'a [u8] {
        let mut end = self.end;
        while end > self.protected {
            let (start, consumed) = self.last(end);
            let part = &self.path[start..end];
            if !part.is_empty() && part != b"." {
                break;
            }
            end -= consumed;
        }
        &self.path[..end]
    }
    pub fn next_back(&mut self) -> Option<Component<'a>> {
        if self.done {
            return None;
        }
        while self.end > self.protected {
            let (start, consumed) = self.last(self.end);
            let part = &self.path[start..self.end];
            self.end -= consumed;
            if part.is_empty() || part == b"." {
                continue;
            }
            return Some(if part == b".." {
                Component::Parent
            } else {
                Component::Normal(part)
            });
        }
        self.end = 0;
        self.done = true;
        if self.root {
            Some(Component::Root)
        } else if self.current {
            Some(Component::Current)
        } else {
            None
        }
    }
}
