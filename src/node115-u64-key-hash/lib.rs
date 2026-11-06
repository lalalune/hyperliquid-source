//! Owned value projection of node115 fresh eight-byte hash; not original Rust ABI.
fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}
pub fn fresh_hash(k0: u64, k1: u64, word: u64) -> u64 {
    let mut v = [
        0x736f6d6570736575 ^ k0,
        0x646f72616e646f6d ^ k1,
        0x6c7967656e657261 ^ k0,
        0x7465646279746573 ^ k1,
    ];
    v[3] ^= word;
    round(&mut v);
    v[0] ^= word;
    let length = 8u64 << 56;
    v[3] ^= length;
    round(&mut v);
    v[0] ^= length;
    v[2] ^= 0xff;
    for _ in 0..3 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}
#[cfg(test)]
mod tests {
    #[test]
    fn frozen_original_return_words() {
        for row in
            include_str!("../../research/work-items/RE-014-u64-key-hash-115/target-smoke.tsv")
                .lines()
        {
            let v: Vec<u64> = row.split('\t').map(|x| x.parse().unwrap()).collect();
            assert_eq!(v.len(), 4);
            assert_eq!(super::fresh_hash(v[0], v[1], v[2]), v[3]);
        }
    }
}
