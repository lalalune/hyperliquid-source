use node115_restart_threshold::*;
use std::task::Poll;
struct Script {
    receive: Poll<ReadyInputs>,
    wait: Poll<()>,
    events: Vec<&'static str>,
    releases: usize,
}
impl Ports for Script {
    fn poll_receive(&mut self) -> Poll<ReadyInputs> {
        self.events.push("receive");
        self.receive
    }
    fn poll_wait(&mut self) -> Poll<()> {
        self.events.push("wait");
        self.wait
    }
    fn release_message(&mut self) {
        self.events.push("release");
        self.releases += 1;
    }
}
fn script(setting: u64, elapsed: f64, allocated: bool) -> Script {
    Script {
        receive: Poll::Ready(ReadyInputs {
            setting,
            elapsed_for_comparison: elapsed,
            message_allocated: allocated,
        }),
        wait: Poll::Pending,
        events: vec![],
        releases: 0,
    }
}
#[test]
fn threshold_grid_checked_with_wide_integer_oracle() {
    for old in 0..256u64 {
        for setting in 0..256u64 {
            let mut machine = Machine::receiving(Counters {
                at_b0: 0,
                at_b8: old,
            });
            let mut io = script(setting, 1.0, true);
            assert_eq!(machine.poll(&mut io), SlicePoll::Pending);
            let wide_next = (old as u128 + 1).min(u64::MAX as u128);
            let crossed = wide_next >= if setting == 0 { 1 } else { setting as u128 };
            assert_eq!(
                machine.counters().at_b8,
                if crossed { 0 } else { wide_next as u64 }
            );
            assert_eq!(machine.message_live(), !crossed);
            assert_eq!(io.releases, usize::from(crossed));
        }
    }
}
#[test]
fn full_width_threshold_and_allocation_boundaries() {
    let values = [0, 1, 2, u64::MAX - 2, u64::MAX - 1, u64::MAX];
    for old in values {
        for setting in values {
            for allocated in [false, true] {
                let mut m = Machine::receiving(Counters {
                    at_b0: u64::MAX,
                    at_b8: old,
                });
                let mut io = script(setting, 600.0, allocated);
                m.poll(&mut io);
                let n = (old as u128 + 1).min(u64::MAX as u128);
                let threshold = (setting as u128).max(1);
                assert_eq!(
                    m.counters(),
                    Counters {
                        at_b0: u64::MAX,
                        at_b8: if n >= threshold { 0 } else { n as u64 }
                    }
                );
                assert_eq!(io.releases, usize::from(n >= threshold && allocated));
                io.wait = Poll::Ready(());
                assert_eq!(m.poll(&mut io), SlicePoll::NextLoop);
                assert_eq!(io.releases, usize::from(allocated)); // Exactly one eventual release.
                assert!(!m.message_live());
            }
        }
    }
}
#[test]
fn ordered_600_boundary_and_conditional_nonfinite_inputs() {
    for (elapsed, clears) in [
        (600.0, false),
        (f64::from_bits(600.0f64.to_bits() - 1), false),
        (f64::from_bits(600.0f64.to_bits() + 1), true),
        (f64::INFINITY, true),
        (f64::NEG_INFINITY, false),
        (f64::NAN, false),
        (-0.0, false),
    ] {
        for old in [0, 10, u64::MAX] {
            let mut m = Machine::receiving(Counters {
                at_b0: old,
                at_b8: 0,
            });
            let mut io = script(10, elapsed, false);
            m.poll(&mut io);
            assert_eq!(
                m.counters().at_b0,
                if clears {
                    0
                } else {
                    (old as u128 + 1).min(u64::MAX as u128) as u64
                }
            );
        }
    }
}
#[test]
fn receive_pending_is_unchanged_and_ready_polls_wait_in_same_call() {
    let mut m = Machine::receiving(Counters { at_b0: 2, at_b8: 3 });
    let original = (m.counters(), m.phase(), m.message_live());
    let mut io = script(99, 1.0, true);
    let ready = io.receive;
    io.receive = Poll::Pending;
    for _ in 0..3 {
        assert_eq!(m.poll(&mut io), SlicePoll::Pending);
        assert_eq!((m.counters(), m.phase(), m.message_live()), original);
    }
    assert_eq!(io.events, vec!["receive"; 3]);
    io.events.clear();
    io.receive = ready;
    assert_eq!(m.poll(&mut io), SlicePoll::Pending);
    assert_eq!(io.events, ["receive", "wait"]);
    assert_eq!(m.counters(), Counters { at_b0: 3, at_b8: 4 });
    assert!(m.message_live());
}
#[test]
fn later_wait_resume_skips_counter_setting_and_message_construction() {
    for setting in [1, 99] {
        let mut m = Machine::receiving(Counters { at_b0: 2, at_b8: 3 });
        let mut io = script(setting, 1.0, true);
        assert_eq!(m.poll(&mut io), SlicePoll::Pending);
        let snapshot = (m.counters(), m.phase(), m.message_live());
        let releases = io.releases;
        io.events.clear();
        // A different supplied receive value must not be consulted on state4.
        io.receive = Poll::Ready(ReadyInputs {
            setting: 0,
            elapsed_for_comparison: f64::INFINITY,
            message_allocated: true,
        });
        for _ in 0..100 {
            assert_eq!(m.poll(&mut io), SlicePoll::Pending);
            assert_eq!((m.counters(), m.phase(), m.message_live()), snapshot);
        }
        assert_eq!(io.events, vec!["wait"; 100]);
        assert_eq!(io.releases, releases);
        io.events.clear();
        io.wait = Poll::Ready(());
        assert_eq!(m.poll(&mut io), SlicePoll::NextLoop);
        assert_eq!(io.releases, 1);
        assert_eq!(m.counters(), snapshot.0);
        assert_eq!(
            io.events,
            if setting == 1 {
                vec!["wait"]
            } else {
                vec!["wait", "release"]
            }
        );
    }
}
#[test]
fn crossed_release_precedes_wait_and_no_enclosing_future_claim() {
    let mut m = Machine::receiving(Counters { at_b0: 0, at_b8: 0 });
    let mut io = script(0, 0.0, true);
    io.wait = Poll::Ready(());
    assert_eq!(m.poll(&mut io), SlicePoll::NextLoop);
    assert_eq!(io.events, ["receive", "release", "wait"]);
    io.events.clear();
    assert_eq!(m.poll(&mut io), SlicePoll::NextLoop);
    assert!(io.events.is_empty());
}
