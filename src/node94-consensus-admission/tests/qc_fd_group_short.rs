use node94_consensus_admission::qc_fd_group::{read_mode1_fd_group_outcome, FdGroupOutcome};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    s.as_bytes().chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()).collect()
}

#[test]
fn all36_frozen_short_fd_and_eof_active_states() {
    let inputs = include_str!("../../../research/work-items/RE-008-qc-fd-group-short-94/inputs.tsv");
    let expected = include_str!("../../../research/work-items/RE-008-qc-fd-group-short-94/expected.tsv");
    assert_eq!(inputs.lines().count(), 37);
    assert_eq!(expected.lines().count(), 37);
    for (i, e) in inputs.lines().skip(1).zip(expected.lines().skip(1)) {
        let i: Vec<_> = i.split('\t').collect();
        let e: Vec<_> = e.split('\t').collect();
        assert_eq!(i[0], e[0]);
        let mut charge = i[1].parse().unwrap();
        let wire = unhex(i[3]);
        let mut input = wire.as_slice();
        let result = read_mode1_fd_group_outcome(&mut charge, i[2].parse().unwrap(), &mut input);
        assert_eq!(result, FdGroupOutcome::Incomplete { needed: e[7].parse().unwrap() }, "{}", i[0]);
        assert_eq!(result.observed_short_fields(), Some((e[5].parse().unwrap(), e[6].parse().unwrap(), e[7].parse().unwrap())));
        assert_eq!(charge, e[1].parse::<u64>().unwrap());
        assert_eq!(wire.len() - input.len(), e[2].parse::<usize>().unwrap());
        assert_eq!(input.len(), e[3].parse::<usize>().unwrap());
        assert_eq!(input, unhex(e[4]));
    }
}

#[test]
fn outcome_api_retains_existing_eight_complete_group_vectors() {
    let inputs = include_str!("../../../research/work-items/RE-008-qc-fd-group-success-94/inputs.tsv");
    let expected = include_str!("../../../research/work-items/RE-008-qc-fd-group-success-94/expected.tsv");
    for (i, e) in inputs.lines().skip(1).zip(expected.lines().skip(1)) {
        let i: Vec<_> = i.split('\t').collect();
        let e: Vec<_> = e.split('\t').collect();
        let mut charge = i[1].parse().unwrap();
        let wire = unhex(i[3]);
        let mut input = wire.as_slice();
        let FdGroupOutcome::Complete(words) = read_mode1_fd_group_outcome(&mut charge, i[2].parse().unwrap(), &mut input) else { panic!("{}", i[0]); };
        let mut view = vec![0u8; 8];
        view.extend(words.iter().flat_map(|word| word.to_le_bytes()));
        assert_eq!(view, unhex(e[4]));
        assert_eq!(charge, e[1].parse::<u64>().unwrap());
        assert_eq!(wire.len() - input.len(), 36);
        assert_eq!(input, unhex(e[3]));
    }
}

#[test]
fn outside_domain_atomic_rejection_is_only_a_chosen_api_behavior() {
    for (charge_before, limit, wire) in [(u64::MAX - 31, u64::MAX, vec![]), (0, 31, vec![0xfd]), (0, 32, vec![0xfc])] {
        let mut charge = charge_before;
        let mut input = wire.as_slice();
        assert_eq!(read_mode1_fd_group_outcome(&mut charge, limit, &mut input), FdGroupOutcome::OutsideDomain);
        assert_eq!(charge, charge_before);
        assert_eq!(input, wire);
    }
}
