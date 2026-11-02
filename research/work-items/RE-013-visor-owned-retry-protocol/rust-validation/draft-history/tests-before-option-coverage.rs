use std::cell::{Cell, RefCell};
use std::rc::Rc;
use visor_retry_protocol::{RetryOutcome, SleepRefusal, SleepReply, retry, retry_owned};

fn complete() -> SleepReply {
    SleepReply {
        code: 0,
        remaining_seconds: -1,
        remaining_nanoseconds: -1,
    }
}

struct Mark(&'static str, Rc<RefCell<Vec<&'static str>>>);
impl Drop for Mark {
    fn drop(&mut self) {
        self.1.borrow_mut().push(self.0);
    }
}

#[test]
fn initial_success_never_reaches_sleep_or_builder() {
    let request = Rc::new(vec![0, 255]);
    let witness = Rc::downgrade(&request);
    let outcome: RetryOutcome<()> = retry(
        &request,
        "unused",
        Some(&[u64::MAX]),
        |seen| {
            assert_eq!(Rc::as_ptr(seen), witness.as_ptr());
            Ok::<(), ()>(())
        },
        |_| panic!("unused sleep"),
        |_, _, _| panic!("unused builder"),
    );
    assert_eq!(outcome, RetryOutcome::Succeeded);
    assert_eq!(witness.strong_count(), 1);
}

#[test]
fn none_uses_exact_defaults_and_empty_is_distinct() {
    for (delays, expected) in [
        (None, vec![(0, 1_000_000), (0, 50_000_000), (1, 0)]),
        (Some(&[][..]), vec![]),
    ] {
        let mut sleeps = Vec::new();
        let result = retry(
            &(),
            "x",
            delays,
            |_| Err(()),
            |r| {
                sleeps.push((r.seconds(), r.nanoseconds()));
                complete()
            },
            |desc, all, _| {
                assert_eq!(desc, "x");
                all.to_vec()
            },
        );
        assert_eq!(sleeps, expected);
        let RetryOutcome::Exhausted(words) = result else {
            panic!("exhaustion")
        };
        assert_eq!(
            words,
            if delays.is_none() {
                vec![0x3f50624dd2f1a9fc, 0x3fa999999999999a, 0x3ff0000000000000]
            } else {
                vec![]
            }
        );
    }
}

#[test]
fn replacement_created_before_old_drop_and_terminal_keeps_identity() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut calls = 0;
    let previous = RefCell::new(None::<std::rc::Weak<Mark>>);
    let terminal_witness = RefCell::new(None);
    let result = retry(
        &(),
        "raw\0λ",
        Some(&[0]),
        |_| {
            if let Some(w) = previous.borrow().as_ref() {
                assert_eq!(w.strong_count(), 1);
            }
            calls += 1;
            events
                .borrow_mut()
                .push(if calls == 1 { "create1" } else { "create2" });
            let e = Rc::new(Mark(
                if calls == 1 { "drop1" } else { "drop2" },
                Rc::clone(&events),
            ));
            *previous.borrow_mut() = Some(Rc::downgrade(&e));
            Err(e)
        },
        |_| panic!("zero sleep"),
        |desc, all, error| {
            assert_eq!(desc, "raw\0λ");
            assert_eq!(all, &[0]);
            assert_eq!(
                Rc::as_ptr(error),
                previous.borrow().as_ref().unwrap().as_ptr()
            );
            events.borrow_mut().push("terminal");
            let t = Rc::new(77);
            *terminal_witness.borrow_mut() = Some(Rc::downgrade(&t));
            t
        },
    );
    let RetryOutcome::Exhausted(t) = result else {
        panic!("exhaustion")
    };
    assert_eq!(
        Rc::as_ptr(&t),
        terminal_witness.borrow().as_ref().unwrap().as_ptr()
    );
    assert_eq!(
        *events.borrow(),
        vec!["create1", "create2", "drop1", "terminal", "drop2"]
    );
}

#[test]
fn zero_and_nonfinite_words_allow_attempt_without_sleep() {
    let calls = Cell::new(0);
    let words = [
        0,
        0x8000000000000000,
        0x7ff0000000000001,
        0xfff0000000000000,
    ];
    let result = retry(
        &(),
        "x",
        Some(&words),
        |_| {
            calls.set(calls.get() + 1);
            Err(())
        },
        |_| panic!("zero-duration sleep"),
        |_, all, _| all.to_vec(),
    );
    assert_eq!(calls.get(), 5);
    assert_eq!(result, RetryOutcome::Exhausted(words.to_vec()));
}

#[test]
fn code_zero_ignores_remainder_and_large_seconds_keep_tail() {
    let mut requests = Vec::new();
    let calls = Cell::new(0);
    let outcome: RetryOutcome<()> = retry(
        &(),
        "x",
        Some(&[0x43efffffffffffff]),
        |_| {
            let n = calls.get();
            calls.set(n + 1);
            if n == 0 { Err(()) } else { Ok(()) }
        },
        |r| {
            requests.push((r.seconds(), r.nanoseconds(), r.clock(), r.flags()));
            complete()
        },
        |_, _, _| panic!("not exhausted"),
    );
    assert_eq!(outcome, RetryOutcome::Succeeded);
    assert_eq!(
        requests,
        vec![
            (i64::MAX as u64, 0, 1, 0),
            (9_223_372_036_854_773_761, 0, 1, 0)
        ]
    );
}

#[test]
fn equal_interruptions_and_subsecond_remainder_preserve_request() {
    let mut requests = Vec::new();
    let mut n = 0;
    let _: RetryOutcome<()> = retry(
        &(),
        "x",
        Some(&[0x3ff0000000000000]),
        |_| Err(()),
        |r| {
            requests.push((r.seconds(), r.nanoseconds()));
            n += 1;
            match n {
                1 | 2 => SleepReply {
                    code: 4,
                    remaining_seconds: 1,
                    remaining_nanoseconds: 0,
                },
                3 => SleepReply {
                    code: 4,
                    remaining_seconds: 0,
                    remaining_nanoseconds: 999_999_999,
                },
                _ => complete(),
            }
        },
        |_, _, _| (),
    );
    assert_eq!(requests, vec![(1, 0), (1, 0), (1, 0), (0, 999_999_999)]);
}

#[test]
fn invalid_remainders_are_new_refusals_without_builder() {
    for (s, n) in [(-1, 0), (0, -1), (0, 1_000_000_000), (2, 0), (1, 1)] {
        let result: RetryOutcome<()> = retry(
            &(),
            "x",
            Some(&[0x3ff0000000000000]),
            |_| Err(()),
            |_| SleepReply {
                code: 4,
                remaining_seconds: s,
                remaining_nanoseconds: n,
            },
            |_, _, _| panic!("refusal has no terminal"),
        );
        assert_eq!(
            result,
            RetryOutcome::Refused(SleepRefusal::InvalidRemainder)
        );
    }
}

#[test]
fn owned_cleanup_preserves_terminal_and_drops_error_before_cleanup_value() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let command = Rc::new(Mark("command", Rc::clone(&events)));
    let cw = Rc::downgrade(&command);
    let cleanup = Rc::new(Mark("cleanup-value", Rc::clone(&events)));
    let pw = Rc::downgrade(&cleanup);
    let tw = RefCell::new(None);
    let mut observed = Vec::new();
    let result = retry_owned(
        command,
        Some(cleanup),
        |c, option| {
            assert_eq!(Rc::as_ptr(c), cw.as_ptr());
            assert_eq!(option, 0);
            Err(())
        },
        |r| {
            observed.push(r.seconds());
            complete()
        },
        |desc, all, _| {
            assert_eq!(desc, "shell::wait_retry");
            assert_eq!(
                all,
                &[0x3ff0000000000000, 0x4008000000000000, 0x4024000000000000]
            );
            let t = Rc::new(9);
            *tw.borrow_mut() = Some(Rc::downgrade(&t));
            t
        },
        |p| {
            assert_eq!(cw.strong_count(), 0);
            assert_eq!(Rc::as_ptr(p), pw.as_ptr());
            assert_eq!(tw.borrow().as_ref().unwrap().strong_count(), 1);
            events.borrow_mut().push("cleanup-call");
            Err(Mark("cleanup-error", Rc::clone(&events)))
        },
    );
    let RetryOutcome::Exhausted(t) = result else {
        panic!("exhaustion")
    };
    assert_eq!(Rc::as_ptr(&t), tw.borrow().as_ref().unwrap().as_ptr());
    assert_eq!(observed, vec![1, 3, 10]);
    assert_eq!(
        *events.borrow(),
        vec!["command", "cleanup-call", "cleanup-error", "cleanup-value"]
    );
}

#[test]
fn absent_cleanup_is_lazy_but_empty_present_cleanup_runs() {
    for present in [false, true] {
        let calls = Cell::new(0);
        let outcome: RetryOutcome<()> = retry_owned(
            Vec::<u8>::new(),
            present.then(Vec::<u8>::new),
            |_, _| Ok::<(), ()>(()),
            |_| panic!("initial success"),
            |_, _, _| panic!("initial success"),
            |p| {
                assert!(p.is_empty());
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            },
        );
        assert_eq!(outcome, RetryOutcome::Succeeded);
        assert_eq!(calls.get(), usize::from(present));
    }
}

#[test]
fn owned_refusal_drops_command_then_value_without_cleanup() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let result: RetryOutcome<()> = retry_owned(
        Mark("command", Rc::clone(&events)),
        Some(Mark("cleanup-value", Rc::clone(&events))),
        |_, _| Err(Mark("error", Rc::clone(&events))),
        |_| SleepReply {
            code: i32::MIN,
            remaining_seconds: 0,
            remaining_nanoseconds: 0,
        },
        |_, _, _| panic!("refusal"),
        |_| -> Result<(), ()> { panic!("refusal skips cleanup") },
    );
    assert_eq!(
        result,
        RetryOutcome::Refused(SleepRefusal::UnexpectedSleepCode(i32::MIN))
    );
    assert_eq!(*events.borrow(), vec!["error", "command", "cleanup-value"]);
}
