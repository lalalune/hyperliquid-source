use node94_consensus_admission::qc_mode0_group::{read_mode0_group, Mode0GroupOutcome};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    s.as_bytes().chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()).collect()
}

#[test]
fn frozen96_values_cursors_and_active_short_fields() {
    let inputs = include_str!("../../../research/work-items/RE-008-qc-mode0-group-94/pre-rust/inputs.tsv");
    let expected = include_str!("../../../research/work-items/RE-008-qc-mode0-group-94/pre-rust/expected.tsv");
    assert_eq!(inputs.lines().count(), 97);
    assert_eq!(expected.lines().count(), 97);
    let mut counts = [0, 0];
    for (i, e) in inputs.lines().skip(1).zip(expected.lines().skip(1)) {
        let i: Vec<_> = i.split('\t').collect();
        let e: Vec<_> = e.split('\t').collect();
        assert_eq!(i[0], e[0]);
        let mut charge = i[2].parse().unwrap();
        let wire = unhex(i[4]);
        let mut input = wire.as_slice();
        let result = read_mode0_group(i[1].parse().unwrap(), &mut charge, i[3].parse().unwrap(), &mut input);
        match result {
            Mode0GroupOutcome::Complete(words) => {
                assert_eq!(e[5], "0");
                let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
                assert_eq!(bytes, unhex(e[11]), "{}", i[0]);
                counts[0] += 1;
            }
            Mode0GroupOutcome::Incomplete { needed } => {
                assert_eq!(result.observed_short_fields(), Some((1, 0, e[7].parse().unwrap())));
                assert_eq!(needed, e[7].parse().unwrap(), "{}", i[0]);
                counts[1] += 1;
            }
            Mode0GroupOutcome::OutsideDomain => panic!("{}", i[0]),
        }
        assert_eq!(charge, e[1].parse::<u64>().unwrap(), "{}", i[0]);
        assert_eq!(wire.len() - input.len(), e[2].parse::<usize>().unwrap(), "{}", i[0]);
        assert_eq!(input.len(), e[3].parse::<usize>().unwrap());
        assert_eq!(input, unhex(e[4]));
    }
    assert_eq!(counts, [36, 60]);
}

#[test]
fn full_mode_word_and_unsupported_markers_are_only_api_exclusions() {
    for (mode, bytes) in [(1u64 << 32, "01020304"), (1, "01020304"), (0, "fe01020304"), (0, "010203ff")] {
        let wire = unhex(bytes);
        let mut input = wire.as_slice();
        let mut charge = u64::MAX;
        assert_eq!(read_mode0_group(mode, &mut charge, 0, &mut input), Mode0GroupOutcome::OutsideDomain);
        assert_eq!(charge, u64::MAX);
        assert_eq!(input, wire);
    }
}

#[test]
fn suffix_or_unread_payload_bytes_do_not_expand_the_marker_domain() {
    for bytes in ["01020304feff", "fb01fe020304"] {
        let wire = unhex(bytes);
        let mut input = wire.as_slice();
        let mut charge = 7;
        assert!(matches!(read_mode0_group(0, &mut charge, 0, &mut input), Mode0GroupOutcome::Complete(_)));
        assert_eq!(charge, 7);
    }
    let mut short = &[0xfd, 0xfe, 0xff][..];
    let mut charge = u64::MAX;
    assert_eq!(read_mode0_group(0, &mut charge, 0, &mut short), Mode0GroupOutcome::Incomplete { needed: 6 });
    assert_eq!(short, [0xfe, 0xff]);
    assert_eq!(charge, u64::MAX);
}
