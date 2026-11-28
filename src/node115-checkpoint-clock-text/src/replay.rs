//! Clock-field update from the selected node #115 replay begin path.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockWords {
    pub date_word: u32,
    pub seconds: u32,
    pub nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointClocks {
    /// Context time, at state +0x60.
    pub current: ClockWords,
    /// Context prev_time, at state +0x6c.
    pub previous: ClockWords,
}

impl CheckpointClocks {
    /// Apply the selected begin-path clock stores to an already decoded pair.
    /// Return whether this input replaced the current clock.
    pub fn advance_for_replay(&mut self, incoming: ClockWords) -> bool {
        let candidate = (incoming.date_word as i32, incoming.seconds, incoming.nanos);
        let current = (
            self.current.date_word as i32,
            self.current.seconds,
            self.current.nanos,
        );
        if candidate <= current {
            return false;
        }
        self.previous = self.current;
        self.current = incoming;
        true
    }
}
