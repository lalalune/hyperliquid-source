//! Boundary outputs were frozen before hash source, with synthetic supplied seeds.
//! These are not captured-node runs or admitted runtime hash-table states.
use node94_margin_risk::hash20::table_hash20;

#[test]
fn fresh20_public_api_matches_pre_source_boundary_vectors() {
    let ramp = core::array::from_fn(|index| index as u8);
    let mut high_tail = [0u8; 20];
    high_tail[16..].fill(255);
    let mut low_body = [255u8; 20];
    low_body[16..].fill(0);
    let messages = [[0u8; 20], [255u8; 20], ramp, high_tail, low_body];
    let seeds: [[u64; 2]; 6] = [
        [0x0000000000000000, 0x0000000000000000],
        [0x0000000000000000, 0x0000000000000001],
        [0x0000000000000001, 0x0000000000000000],
        [0x0706050403020100, 0x0f0e0d0c0b0a0908],
        [0xffffffffffffffff, 0xffffffffffffffff],
        [0x8000000000000000, 0x0000000000000001],
    ];
    let expected: [[u64; 5]; 6] = [
        [
            0x24de1cc795c400b0,
            0xa5e5f4ef8d505a1f,
            0x639e355ae68c0100,
            0x6920ae26a10cf66d,
            0x53d89ed114d418e3,
        ],
        [
            0x2b37c6dca5f5728e,
            0xde3e51856deda358,
            0xe7e5566f76ce164c,
            0x286ef191215f62df,
            0x12937444bce82226,
        ],
        [
            0x901a02585a27fba3,
            0x7780d26063272bf1,
            0xd0c112e9e4038c40,
            0xbb4b9c65186d6fd6,
            0xa023c7a829e3430f,
        ],
        [
            0xff00698b87b3f834,
            0x1122b749fb80dfc1,
            0xc0dc2f46a6cce040,
            0x6536a9880902b89c,
            0xdfab7d4b394f9803,
        ],
        [
            0x024af6ba1517ced4,
            0x48c7921099d66320,
            0x79dd5974d876d0e4,
            0x1f1767f59fddaadd,
            0xee821c7260d1cdfc,
        ],
        [
            0xc2f27c614b1ba02e,
            0x05cb61e29b907438,
            0x2afcb2b65fdd382c,
            0x08c20b6f11cb6992,
            0x95d06045904df725,
        ],
    ];
    for (seed, outputs) in seeds.into_iter().zip(expected) {
        for (message, expected_hash) in messages.iter().zip(outputs) {
            assert_eq!(table_hash20(seed, message), expected_hash);
        }
    }
}
