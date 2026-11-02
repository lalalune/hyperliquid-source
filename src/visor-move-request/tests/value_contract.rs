use visor_move_request::{
    admitted_output_bound, encode_admitted_move, EncodeError, MAX_COMBINED_INPUT_BYTES,
};

#[test]
fn preserves_original_nonblank_operands_and_order() {
    let request = encode_admitted_move(" a ", "b").unwrap();
    assert_eq!(request.command_bytes(), b"mv ' a ' b");
    assert_eq!(request.option_byte(), 1);
}

#[test]
fn omits_exact_blank_domain_without_normalizing_other_scalars() {
    assert_eq!(
        encode_admitted_move("\u{85}\u{2000}", "\t")
            .unwrap()
            .command_bytes(),
        b"mv"
    );
    assert_eq!(
        encode_admitted_move("\u{200b}", "")
            .unwrap()
            .command_bytes(),
        "mv '\u{200b}'".as_bytes()
    );
}

#[test]
fn caret_conflicts_and_double_backslash_are_distinct() {
    assert_eq!(
        encode_admitted_move("a^b", "^^").unwrap().command_bytes(),
        b"mv a'^b' '^''^'"
    );
    assert_eq!(
        encode_admitted_move("\\", "'$").unwrap().command_bytes(),
        b"mv \"\\\\\" \"'\"'$'"
    );
}

#[test]
fn nul_is_rejected_in_either_original_operand() {
    for (source, destination) in [(" \0 ", "a"), ("a", "\0"), ("", "\0\t")] {
        assert!(matches!(
            encode_admitted_move(source, destination),
            Err(EncodeError::EmbeddedNul)
        ));
    }
}

#[test]
fn raw_option_does_not_remove_the_quiet_substring() {
    let request = encode_admitted_move("2>&1", "").unwrap();
    assert_eq!(request.command_bytes(), b"mv '2>&1'");
    assert_eq!(request.option_byte(), 1);
}

#[test]
fn exact_length_bound_and_checked_addition() {
    assert_eq!(admitted_output_bound(0, 0), Ok(4));
    assert_eq!(
        admitted_output_bound(MAX_COMBINED_INPUT_BYTES - 1, 1),
        Ok((1_u64 << 63) - 4)
    );
    assert!(admitted_output_bound(MAX_COMBINED_INPUT_BYTES, 1).is_err());
    assert!(admitted_output_bound(u64::MAX, 1).is_err());
}
