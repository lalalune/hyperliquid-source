//! Selected node115 restart counter/threshold and pending-resume slice.
//!
//! This models outer state 3, nested states 3/4 of `2aeaef0`, ending when the
//! later wait is ready. Provider outputs are explicit; no timer, JSON parser,
//! formatter, allocator, full scheduler, or enclosing Future is reconstructed.
use std::task::Poll;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub at_b0: u64,
    pub at_b8: u64,
}

/// Values available after the first wait completes and opaque preparation has
/// finished. `elapsed_for_comparison` is xmm1 at 2aeffc2, after native elapsed
/// normalization; supplying arbitrary NaNs is a conditional branch test, not
/// a claim that those values reach this point through the native producer.
#[derive(Debug, Clone, Copy)]
pub struct ReadyInputs {
    pub elapsed_for_comparison: f64,
    /// Successful u64 parser result, before wrapper clamps zero to one.
    pub setting: u64,
    /// Nonzero capacity of the newly formatted message at +138.
    pub message_allocated: bool,
}

/// Opaque prerequisites and effects. Ready inputs combine operations between
/// the first ready poll and the selected counter slice; no readiness, timing,
/// parsing, formatting, or memory-release semantics are invented here.
pub trait Ports {
    fn poll_receive(&mut self) -> Poll<ReadyInputs>;
    fn poll_wait(&mut self) -> Poll<()>;
    fn release_message(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Receive,
    Wait,
    NextLoop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlicePoll {
    Pending,
    /// Control leaves this selected slice; the enclosing future may continue.
    NextLoop,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Machine {
    counters: Counters,
    phase: Phase,
    message_live: bool,
    message_allocated: bool,
}

impl Machine {
    /// Resume at nested state 3 with supplied counters. The earlier preparation
    /// and counter initialization path are caller responsibilities.
    pub fn receiving(counters: Counters) -> Self {
        Self {
            counters,
            phase: Phase::Receive,
            message_live: false,
            message_allocated: false,
        }
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn message_live(&self) -> bool {
        self.message_live
    }

    /// A ready receive continues into the later wait in this same call. Once
    /// waiting, resume bypasses the receive/config/counter work. The Ports must
    /// not unwind; native unwind/destructor behavior is outside this contract.
    pub fn poll(&mut self, ports: &mut impl Ports) -> SlicePoll {
        if self.phase == Phase::Receive {
            let Poll::Ready(input) = ports.poll_receive() else {
                return SlicePoll::Pending;
            };
            self.counters.at_b0 = if input.elapsed_for_comparison > 600.0 {
                0
            } else {
                self.counters.at_b0.saturating_add(1)
            };
            self.counters.at_b8 = self.counters.at_b8.saturating_add(1);
            self.message_live = true;
            self.message_allocated = input.message_allocated;
            if self.counters.at_b8 >= input.setting.max(1) {
                self.message_live = false;
                if self.message_allocated {
                    ports.release_message();
                }
                self.counters.at_b8 = 0;
            }
            self.phase = Phase::Wait;
        }
        if self.phase == Phase::Wait {
            if ports.poll_wait().is_pending() {
                return SlicePoll::Pending;
            }
            if self.message_live && self.message_allocated {
                ports.release_message();
            }
            self.message_live = false;
            self.phase = Phase::NextLoop;
        }
        SlicePoll::NextLoop
    }
}
