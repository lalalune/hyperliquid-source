use node115_checkpoint_clock_text::{
    CompactClockError, read_compact_checkpoint_clocks, render_checkpoint_clock,
};

#[test]
fn materialized_clock_read_preserves_both_full_native_words() {
    let mut state = vec![0x5a; 0x42c8];
    state[0x28..0x30].copy_from_slice(&42_u64.to_le_bytes());
    let current = [0x00fd_402a_u32, 11_045, 321];
    let previous = [0x00fc_16e3_u32, 86_399, 1_123_000_000];
    for (index, word) in current.into_iter().chain(previous).enumerate() {
        let offset = 0x60 + 4 * index;
        state[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }

    let [now, old] = read_compact_checkpoint_clocks(&state, 42).unwrap();
    assert_eq!((now, old), (current, previous));
    assert_eq!(
        render_checkpoint_clock(now[0], now[1], now[2])
            .unwrap()
            .as_str(),
        "2026-01-02T03:04:05.000000321"
    );
    assert_eq!(
        render_checkpoint_clock(old[0], old[1], old[2])
            .unwrap()
            .as_str(),
        "2016-12-31T23:59:60.123"
    );
    assert_eq!(
        read_compact_checkpoint_clocks(&state, 41),
        Err(CompactClockError::HeightMismatch {
            expected: 41,
            actual: 42
        }),
    );
    assert_eq!(
        read_compact_checkpoint_clocks(&state[..0x77], 42),
        Err(CompactClockError::WrongSize { actual: 0x77 }),
    );
}
