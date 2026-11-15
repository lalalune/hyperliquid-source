//! The stake-set provider `0x595e5c0` (slot `0x64e64b0`): which stake set applies to a round.
//!
//! The state holds a history of stake sets keyed by round (a tree, or a ring of 0x40 byte records: round at
//! `+0`, the stake set at `+8`), a base round at `+0x20`, an execution round at `+0x60` and a warning
//! counter at `+0x68`. For a query round `r` the provider computes a lookup round `q` from the base, then
//! returns the stored set with the greatest round `<= q`. The history search itself (`0x4dce480`, the
//! range builders and extractors `0x51f5620`, `0x57f35c0`) is modelled from `RE-008-proposer-selection-115`
//! and not re-read here; the window arithmetic and the result mapping are pinned in
//! `relations-provider.tsv`.

use std::cell::Cell;
use std::collections::BTreeMap;

use crate::certificate::Context;
use crate::stake::StakeSet;
use crate::verifier::StakeSetProvider;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rounds {
    Tree(BTreeMap<u64, StakeSet>),
    /// `rows.len()` is the capacity; live rows are `len` rows from `head`, wrapping, rounds strictly increasing.
    Ring { rows: Vec<(u64, StakeSet)>, head: usize, len: usize },
}

impl Rounds {
    pub fn tree(entries: impl IntoIterator<Item = (u64, StakeSet)>) -> Self {
        Rounds::Tree(entries.into_iter().collect())
    }

    /// `None` unless `len <= capacity`, `head < capacity` (0 for capacity 0) and the live rounds increase.
    /// Unused capacity rows may hold anything (the native search does not read them).
    pub fn ring(rows: Vec<(u64, StakeSet)>, head: usize, len: usize) -> Option<Self> {
        let cap = rows.len();
        if len > cap || !(head < cap || (cap == 0 && head == 0)) {
            return None;
        }
        let ordered = (1..len).all(|i| rows[(head + i - 1) % cap].0 < rows[(head + i) % cap].0);
        ordered.then_some(Rounds::Ring { rows, head, len })
    }

    /// The stored set with the greatest round `<= q`.
    pub fn at_or_below(&self, q: u64) -> Option<&StakeSet> {
        match self {
            Rounds::Tree(m) => m.range(..=q).next_back().map(|(_, s)| s),
            Rounds::Ring { rows, head, len } => {
                let at = |i: usize| &rows[(head + i) % rows.len()];
                let prefix = (0..*len).take_while(|&i| at(i).0 <= q).count();
                prefix.checked_sub(1).map(|i| &at(i).1)
            }
        }
    }
}

/// The part of the state `0x595e5c0` reads and writes.
#[derive(Clone, Debug)]
pub struct StakeHistory {
    pub rounds: Rounds,
    /// `state+0x20`.
    pub base: u64,
    /// `state+0x60`.
    pub execution: u64,
    /// `state+0x68`: incremented (wrapping) on every warning. Natively an atomic increment followed by a
    /// log call; only the value is modelled.
    pub warnings: Cell<u64>,
}

impl StakeHistory {
    pub fn new(rounds: Rounds, base: u64, execution: u64, warnings: u64) -> Self {
        StakeHistory { rounds, base, execution, warnings: Cell::new(warnings) }
    }

    /// `r >= max(min(base + 2000, MAX), min(execution + 201, MAX))`.
    pub fn warns(&self, round: u64) -> bool {
        round >= self.base.saturating_add(2000).max(self.execution.saturating_add(201))
    }

    /// The lookup round: `base` while `r < min(base + 2000, MAX)`, else `max(base, r - 200)` (mod 2^64).
    pub fn lookup_round(&self, round: u64) -> u64 {
        if round < self.base.saturating_add(2000) { self.base } else { self.base.max(round.wrapping_sub(200)) }
    }

    /// One provider call: counts a warning if `r` is at or past the limit, then searches.
    pub fn lookup(&self, round: u64) -> Option<&StakeSet> {
        if self.warns(round) {
            self.warnings.set(self.warnings.get().wrapping_add(1));
        }
        self.rounds.at_or_below(self.lookup_round(round))
    }
}

/// `None` is the provider's tag `0x28` (round at `+8`); `Some` is tag `0x2e` with the set.
impl StakeSetProvider for StakeHistory {
    fn stake_set(&self, _ctx: &Context, round: u64) -> Option<&StakeSet> {
        self.lookup(round)
    }
}
