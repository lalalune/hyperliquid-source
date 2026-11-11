//! Recovered buffered-u32 draw/reseed scheduling, not an RNG implementation.
//!
//! Node #115 evidence: RE-012-rng-buffer-selection-115. The API only runs the
//! established policy state. Entropy acquisition and the block refill remain
//! explicit caller-owned boundaries; no entropy source or fake refill exists.
#![no_std]

/// Logical fields only; this is not a `repr(C)` native layout claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub cursor: u64,
    pub remaining: i64,
    pub base_budget: i64,
    pub observed_epoch: u64,
    pub key_state: [u8; 48],
    pub buffer: [u32; 64],
}

pub enum Step<'a> {
    Word(u32),
    Entropy(EntropyRequest<'a>),
    Refill(RefillRequest<'a>),
}

pub struct EntropyRequest<'a> {
    state: &'a mut State,
    epoch: u64,
}

pub struct RefillRequest<'a> {
    state: &'a mut State,
}

/// `Unavailable` is the normal-return boundary after native error-box cleanup.
/// Allocation failure, panic and unwind behavior of that cleanup are excluded.
pub enum EntropyOutcome {
    Seed([u8; 32]),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetOverflow;

/// A result the caller obtained from a real, separate block-refill provider.
/// The policy does not generate or validate the cryptography of these bytes.
pub struct RefillOutput {
    pub key_state: [u8; 48],
    pub words: [u32; 64],
}

/// Consume a buffered word or stop at the actual entropy/refill boundary.
/// The stored buffer must belong to this key/cursor at the captured call boundary.
pub fn begin(state: &mut State, epoch: u64) -> Step<'_> {
    if state.cursor < 64 {
        let word = state.buffer[state.cursor as usize];
        state.cursor += 1;
        return Step::Word(word);
    }
    // Native `js` observes the subtraction sign bit, not signed-order overflow.
    let difference = state.observed_epoch.wrapping_sub(epoch);
    if state.remaining > 0 && difference & (1_u64 << 63) == 0 {
        state.remaining -= 256;
        Step::Refill(RefillRequest { state })
    } else {
        Step::Entropy(EntropyRequest { state, epoch })
    }
}

impl<'a> EntropyRequest<'a> {
    pub const BYTES: usize = 32;

    pub fn state(&self) -> &State {
        self.state
    }

    /// Resume after entropy acquisition and any normal error-box cleanup.
    /// Successful seed installation and the epoch write precede the checked
    /// budget subtraction; an overflow preserves those earlier state writes.
    pub fn resume(self, outcome: EntropyOutcome) -> Result<RefillRequest<'a>, BudgetOverflow> {
        if let EntropyOutcome::Seed(seed) = outcome {
            self.state.key_state[..32].copy_from_slice(&seed);
            self.state.key_state[32..].fill(0);
        }
        self.state.observed_epoch = self.epoch;
        let next = self
            .state
            .base_budget
            .checked_sub(256)
            .ok_or(BudgetOverflow)?;
        self.state.remaining = next;
        Ok(RefillRequest { state: self.state })
    }
}

impl RefillRequest<'_> {
    /// Six is the native argument, not an asserted algorithm name/round count.
    pub const NATIVE_ARGUMENT: u32 = 6;
    pub const OUTPUT_BYTES: usize = 256;

    pub fn state(&self) -> &State {
        self.state
    }

    /// Resume only after the external block refill returns normally. This call
    /// consumes the request, installs its returned state, then reads word zero.
    /// No success or output is synthesized if the caller does not resume it.
    pub fn complete(self, output: RefillOutput) -> u32 {
        self.state.key_state = output.key_state;
        self.state.buffer = output.words;
        self.state.cursor = 1;
        self.state.buffer[0]
    }
}
