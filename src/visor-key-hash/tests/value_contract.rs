//! Literal expectations were frozen before this source in frozen/corpus.json.
use visor_key_hash::hash_key;

#[test]
fn empty_still_has_suffix_and_length() {
    assert_eq!(hash_key([0, 0], b""), 0x3040_6ea5_23c5_3def);
}

#[test]
fn nul_is_data() {
    assert_eq!(hash_key([0, 0], b"\0"), 0xda57_35e7_144b_8d9f);
}

#[test]
fn existing_ff_does_not_replace_implicit_suffix() {
    assert_eq!(hash_key([0, 0], b"\xff"), 0x1dcb_e1ce_95dc_ba8e);
}

#[test]
fn actual_lookup_names_remain_ordinary_bytes() {
    assert_eq!(hash_key([0, 0], b"skip-download"), 0x07b1_1b17_186b_b227);
    assert_eq!(hash_key([0, 0], b"child-args"), 0x0ca9_c806_7519_f616);
}

#[test]
fn suffix_completes_a_seven_byte_tail() {
    assert_eq!(
        hash_key([0, 0], &[0, 1, 2, 3, 4, 5, 6]),
        0x01e1_6b28_a455_1c5b
    );
}

#[test]
fn complete_word_then_suffix() {
    assert_eq!(
        hash_key([0, 0], &[0, 1, 2, 3, 4, 5, 6, 7]),
        0xa243_5468_dc02_2489
    );
}

#[test]
fn complete_word_then_two_byte_tail() {
    assert_eq!(
        hash_key([0, 0], &[0, 1, 2, 3, 4, 5, 6, 7, 8]),
        0x78a2_012c_10ea_dc36
    );
}

#[test]
fn nonzero_seed_changes_all_selected_paths() {
    let seed = [u64::MAX, 0];
    assert_eq!(hash_key(seed, b""), 0x9ae4_fb58_6e5f_811e);
    assert_eq!(hash_key(seed, b"child-args"), 0x8b82_cebc_ab11_2cf0);
    assert_eq!(
        hash_key(seed, &[0, 1, 2, 3, 4, 5, 6]),
        0xdb3a_0685_1f90_093d
    );
    assert_eq!(
        hash_key(seed, &[0, 1, 2, 3, 4, 5, 6, 7]),
        0x6ff8_b991_5123_0740
    );
}
