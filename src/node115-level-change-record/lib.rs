//! Selected replacement-record prefix and tag-2 consumer, node #115.
//! Opaque bytes are represented as None, never invented as initialized zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Spot,
    Perpetual,
}
impl Route {
    pub const fn record_width(self) -> usize {
        match self {
            Self::Spot => 712,
            Self::Perpetual => 696,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub old_size: u64,
    pub new_size: u64,
    pub object_b0: u64,
    pub caller_word: u64,
    pub object_f0: u64,
    pub identity_f8: [u8; 20],
    pub byte_d2: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub route: Route,
    pub prefix: [Option<u8>; 80],
}
fn write(dst: &mut [Option<u8>], offset: usize, src: &[u8]) {
    for (out, value) in dst[offset..offset + src.len()].iter_mut().zip(src) {
        *out = Some(*value);
    }
}
/// `None` is the equal-size early return before event construction. This
/// projects only the initialized 80-byte prefix of a valid newly appended row;
/// capacity growth and subsequent aggregate arithmetic are outside scope.
pub fn replacement(input: Input, route: Route) -> Option<Record> {
    if input.old_size == input.new_size {
        return None;
    }
    let mut prefix = [None; 80];
    write(&mut prefix, 0, &2u64.to_le_bytes());
    write(&mut prefix, 8, &2u64.to_le_bytes());
    write(&mut prefix, 16, &input.old_size.to_le_bytes());
    write(&mut prefix, 24, &input.new_size.to_le_bytes());
    write(&mut prefix, 32, &input.object_b0.to_le_bytes());
    write(&mut prefix, 40, &input.caller_word.to_le_bytes());
    write(&mut prefix, 48, &input.object_f0.to_le_bytes());
    write(&mut prefix, 56, &input.identity_f8);
    write(&mut prefix, 76, &[input.byte_d2]);
    Some(Record { route, prefix })
}
/// Copies the selected 72-byte tag-2 payload to the common consumer boundary.
/// The selected downstream tag-2 arms immediately return; intervening helper
/// effects, allocation, native pointers and uninitialized bytes remain outside.
pub fn selected_consumer_payload(record: &Record) -> [Option<u8>; 72] {
    record.prefix[8..80].try_into().unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Input {
        Input {
            old_size: 19,
            new_size: 5,
            object_b0: 11,
            caller_word: 12,
            object_f0: 13,
            identity_f8: std::array::from_fn(|i| i as u8),
            byte_d2: 0xc7,
        }
    }
    #[test]
    fn exact_offsets_and_inactive_bytes() {
        for route in [Route::Spot, Route::Perpetual] {
            assert_eq!(
                route.record_width(),
                if route == Route::Spot { 712 } else { 696 }
            );
            let r = replacement(fixture(), route).unwrap();
            let b = r.prefix;
            assert_eq!(b[0..8], 2u64.to_le_bytes().map(Some));
            assert_eq!(b[8..16], 2u64.to_le_bytes().map(Some));
            assert_eq!(b[16..24], 19u64.to_le_bytes().map(Some));
            assert_eq!(b[24..32], 5u64.to_le_bytes().map(Some));
            assert_eq!(b[32..40], 11u64.to_le_bytes().map(Some));
            assert_eq!(b[40..48], 12u64.to_le_bytes().map(Some));
            assert_eq!(b[48..56], 13u64.to_le_bytes().map(Some));
            assert_eq!(
                b[56..76],
                std::array::from_fn::<_, 20, _>(|i| Some(i as u8))
            );
            assert_eq!(b[76], Some(0xc7));
            assert_eq!(b[77..80], [None; 3]);
            assert_eq!(selected_consumer_payload(&r), b[8..80]);
        }
    }
    #[test]
    fn equal_is_no_record_and_every_identity_byte_is_distinct() {
        let mut i = fixture();
        i.new_size = i.old_size;
        assert!(replacement(i, Route::Spot).is_none());
        for bit in 0..160 {
            let mut i = fixture();
            i.identity_f8[bit / 8] ^= 1 << (bit % 8);
            let r = replacement(i, Route::Spot).unwrap();
            assert_eq!(r.prefix[56 + bit / 8], Some(i.identity_f8[bit / 8]));
        }
    }
}
