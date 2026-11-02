use node94_consensus_admission::qc_mode1_group::{read_mode1_group, Mode1GroupOutcome};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    s.as_bytes().chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()).collect()
}

#[test]
fn frozen128_mode1_states_and_qualified_memory_views() {
    let inputs = include_str!("../../../research/work-items/RE-008-qc-mode1-group-94/pre-rust/inputs.tsv");
    let expected = include_str!("../../../research/work-items/RE-008-qc-mode1-group-94/pre-rust/expected.tsv");
    assert_eq!(inputs.lines().count(), 129);
    assert_eq!(expected.lines().count(), 129);
    let mut counts = [0, 0, 0];
    for (i, e) in inputs.lines().skip(1).zip(expected.lines().skip(1)) {
        let i: Vec<_> = i.split('\t').collect();
        let e: Vec<_> = e.split('\t').collect();
        assert_eq!(i[0], e[0]);
        let mut charge = i[2].parse().unwrap();
        let wire = unhex(i[4]);
        let mut group: [u8; 40] = unhex(i[5]).try_into().unwrap();
        let before = group;
        let mut input = wire.as_slice();
        let result = read_mode1_group(i[1].parse().unwrap(), &mut charge, i[3].parse().unwrap(), &mut input);
        match result {
            Mode1GroupOutcome::Complete(words) => {
                let values: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
                assert_eq!(values, unhex(e[11]), "{}", i[0]);
                assert_eq!(e[5], "0");
                counts[0] += 1;
            }
            Mode1GroupOutcome::Incomplete { needed } => {
                assert_eq!(result.observed_error_fields(), Some((1, 0, Some(e[7].parse().unwrap()))));
                assert_eq!(needed, e[7].parse().unwrap());
                counts[1] += 1;
            }
            Mode1GroupOutcome::BudgetDenied => {
                assert_eq!(result.observed_error_fields(), Some((1, 2, None)));
                assert_eq!(e[7], "-");
                assert_eq!(e[10], "-");
                counts[2] += 1;
            }
            Mode1GroupOutcome::OutsideDomain => panic!("{}", i[0]),
        }
        if e[12] == "-" {
            assert!(!result.write_result_view(&mut group));
            assert_eq!(group, before); // Chosen no-view behavior, not native short memory.
        } else {
            assert!(result.write_result_view(&mut group));
            assert_eq!(group.as_slice(), unhex(e[12]), "{}", i[0]);
        }
        assert_eq!(charge, e[1].parse::<u64>().unwrap(), "{}", i[0]);
        assert_eq!(wire.len() - input.len(), e[2].parse::<usize>().unwrap());
        assert_eq!(input.len(), e[3].parse::<usize>().unwrap());
        assert_eq!(input, unhex(e[4]));
    }
    assert_eq!(counts, [41, 63, 24]);
}

#[test]
fn initial_denial_precedes_marker_qualification_and_has_no_need() {
    for (before, limit, after) in [(u64::MAX, 0, u64::MAX), (0, 0, 32)] {
        for wire in [&[][..], &[0xfe][..], &[0xff][..]] {
            let mut input = wire;
            let mut charge = before;
            let result = read_mode1_group(1, &mut charge, limit, &mut input);
            assert_eq!(result, Mode1GroupOutcome::BudgetDenied);
            assert_eq!(result.observed_error_fields(), Some((1, 2, None)));
            assert_eq!(charge, after);
            assert_eq!(input, wire);
            let mut group = [0xa5; 40];
            assert!(result.write_result_view(&mut group));
            assert_eq!(&group[..8], &1u64.to_le_bytes());
            assert_eq!(group[8], 2);
            assert_eq!(&group[9..], &[0xa5; 31]);
        }
    }
}

#[test]
fn outside_domain_refusal_is_only_a_chosen_safe_api() {
    for (mode, wire) in [(0, vec![]), ((1u64 << 32) | 1, vec![]), (1, vec![0xfe]), (1, vec![1, 2, 3, 0xff])] {
        let mut charge = 0;
        let mut input = wire.as_slice();
        let result = read_mode1_group(mode, &mut charge, 32, &mut input);
        assert_eq!(result, Mode1GroupOutcome::OutsideDomain);
        assert_eq!(charge, 0);
        assert_eq!(input, wire);
        let mut group = [0xa5; 40];
        assert!(!result.write_result_view(&mut group));
        assert_eq!(group, [0xa5; 40]);
    }
}
