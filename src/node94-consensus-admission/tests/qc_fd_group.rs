use node94_consensus_admission::qc_fd_group::read_mode1_fd_group;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    s.as_bytes().chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap()).collect()
}

#[test]
fn eight_frozen_native_derived_success_vectors() {
    let inputs = include_str!("../../../research/work-items/RE-008-qc-fd-group-success-94/inputs.tsv");
    let expected = include_str!("../../../research/work-items/RE-008-qc-fd-group-success-94/expected.tsv");
    for (i, e) in inputs.lines().skip(1).zip(expected.lines().skip(1)) {
        let i: Vec<_> = i.split('\t').collect();
        let e: Vec<_> = e.split('\t').collect();
        assert_eq!(i[0], e[0]);
        let mut charge = i[1].parse().unwrap();
        let wire = unhex(i[3]);
        let mut input = wire.as_slice();
        let mut output = unhex(i[4]).try_into().unwrap();
        assert!(read_mode1_fd_group(&mut charge, i[2].parse().unwrap(), &mut input, &mut output));
        assert_eq!(charge, e[1].parse::<u64>().unwrap(), "{} charge", i[0]);
        assert_eq!(wire.len() - input.len(), e[2].parse::<usize>().unwrap(), "{} consumed", i[0]);
        assert_eq!(input, unhex(e[3]), "{} suffix", i[0]);
        assert_eq!(output.as_slice(), unhex(e[4]), "{} all40", i[0]);
    }
}

#[test]
fn chosen_safe_api_rejects_outside_domain_without_mutation() {
    // These checks qualify API behavior only, not native failure paths.
    let wire = [0xfdu8; 36];
    for (c, l, bytes) in [(u64::MAX - 31, u64::MAX, &wire[..]), (0, 31, &wire[..]), (0, 32, &wire[..35])] {
        let mut charge = c;
        let mut input = bytes;
        let mut output = [0x96; 40];
        assert!(!read_mode1_fd_group(&mut charge, l, &mut input, &mut output));
        assert_eq!(charge, c);
        assert_eq!(input, bytes);
        assert_eq!(output, [0x96; 40]);
    }
}
