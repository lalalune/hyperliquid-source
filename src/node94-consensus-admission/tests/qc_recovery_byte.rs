//! Frozen native-derived field-entry expectations, not a captured execution test.
use node94_consensus_admission::qc_recovery_byte::{read_field, ChargeState};

#[test]
fn twelve_frozen_field_boundaries() {
    let rows = include_str!("../../../research/work-items/RE-008-qc-recovery-byte-94/boundaries.csv");
    let mut cases = 0;
    for row in rows.lines().skip(1) {
        let fields: Vec<_> = row.split(',').collect();
        assert_eq!(fields.len(), 11);
        let number = |i: usize| fields[i].parse::<u64>().unwrap();
        let mut state = ChargeState {
            mode: number(1).try_into().unwrap(),
            charge: number(2),
            limit: number(3),
        };
        let storage = [number(5) as u8, (number(5) as u8) ^ 0xa5];
        let original = &storage[..number(4) as usize];
        let mut input = original;
        let result = read_field(&mut state, &mut input);
        assert_eq!(state.charge, number(7), "{} charge", fields[0]);
        assert_eq!(original.len() - input.len(), number(8) as usize, "{} consumed", fields[0]);
        assert_eq!(input, &original[number(8) as usize..], "{} suffix", fields[0]);
        match result {
            Ok(value) => {
                assert_eq!(fields[6], "ok", "{} status", fields[0]);
                assert_eq!(u64::from(value), number(10), "{} byte", fields[0]);
            }
            Err(error) => {
                assert_eq!(fields[6], "error", "{} status", fields[0]);
                assert_eq!(u64::from(error.observed_kind()), number(9), "{} kind", fields[0]);
                assert_eq!(error.observed_error_word(), 1, "{} error word", fields[0]);
            }
        }
        cases += 1;
    }
    assert_eq!(cases, 12);
}
