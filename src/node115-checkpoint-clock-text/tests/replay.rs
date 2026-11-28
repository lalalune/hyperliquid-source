use node115_checkpoint_clock_text::{CheckpointClocks, ClockWords, render_checkpoint_clock};

fn clock(date_word: u32, seconds: u32, nanos: u32) -> ClockWords {
    ClockWords {
        date_word,
        seconds,
        nanos,
    }
}

#[test]
fn rotates_only_on_a_strictly_later_replay_clock() {
    let current = clock(0x00fd_402a, 11_045, 10);
    let previous = clock(0x00fd_402a, 11_044, 0);
    let mut clocks = CheckpointClocks { current, previous };

    for ignored in [
        current,
        clock(0x00fd_401a, 86_399, 0),
        clock(0x00fd_402a, 11_044, 999_999_999),
        clock(0x00fd_402a, 11_045, 9),
    ] {
        assert!(!clocks.advance_for_replay(ignored));
        assert_eq!(clocks, CheckpointClocks { current, previous });
    }

    let later = clock(0x00fd_402a, 11_045, 11);
    assert!(clocks.advance_for_replay(later));
    assert_eq!(clocks.previous, current);
    assert_eq!(clocks.current, later);
    let rendered = render_checkpoint_clock(later.date_word, later.seconds, later.nanos).unwrap();
    assert_eq!(rendered.as_str(), "2026-01-02T03:04:05.000000011");

    let next_day = clock(0x00fd_403a, 0, 0);
    assert!(clocks.advance_for_replay(next_day));
    assert_eq!(clocks.previous, later);
    assert_eq!(clocks.current, next_day);
}

#[test]
fn packed_date_word_is_compared_as_signed() {
    let archived_bce = clock(0xffff_e01b, 86_399, 0);
    let archived_ce = clock(0x0000_2010, 0, 0);
    let mut clocks = CheckpointClocks {
        current: archived_bce,
        previous: clock(0xffff_e01b, 0, 0),
    };
    assert!(clocks.advance_for_replay(archived_ce));
    assert_eq!(clocks.previous, archived_bce);
    assert!(!clocks.advance_for_replay(archived_bce));
    assert_eq!(clocks.current, archived_ce);
}
