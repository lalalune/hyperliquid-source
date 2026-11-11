use node115_peer_address_admission::{Admission, admit, packed_present};
use std::collections::BTreeMap;

#[test]
fn exact_loopback_precedes_lookup() {
    let m = BTreeMap::new();
    assert_eq!(admit(&m, &[1; 20], [127, 0, 0, 1]), Admission::Loopback);
    assert_eq!(admit(&m, &[1; 20], [127, 0, 0, 2]), Admission::Missing);
    assert_eq!(admit(&m, &[1; 20], [127, 0, 1, 1]), Admission::Missing);
}
#[test]
fn exact_key_and_all_address_bytes() {
    let id = [7; 20];
    let ip = [1, 2, 3, 4];
    let m = BTreeMap::from([(id, ip)]);
    assert_eq!(admit(&m, &id, ip), Admission::Matched);
    for i in 0..20 {
        let mut key = id;
        key[i] ^= 1;
        assert_eq!(admit(&m, &key, ip), Admission::Missing);
    }
    for i in 0..4 {
        let mut other = ip;
        other[i] ^= 1;
        assert_eq!(admit(&m, &id, other), Admission::Mismatched);
    }
}
#[test]
fn producer_pack_is_listener_shift_and_low_bit() {
    for ip in [[0, 0, 0, 0], [127, 0, 0, 1], [1, 2, 3, 4], [255; 4]] {
        let raw = packed_present(ip);
        assert_eq!(raw & 1, 1);
        assert_eq!(((raw >> 8) as u32).to_le_bytes(), ip);
    }
}
#[test]
fn selected_map_overrides_neither_stale_nor_absent_entries() {
    let key = [8; 20];
    let m = BTreeMap::from([(key, [1, 2, 3, 4])]);
    assert_eq!(admit(&m, &key, [1, 2, 3, 4]), Admission::Matched);
    assert_eq!(admit(&m, &key, [5, 6, 7, 8]), Admission::Mismatched);
    assert_eq!(admit(&m, &[9; 20], [1, 2, 3, 4]), Admission::Missing);
}
