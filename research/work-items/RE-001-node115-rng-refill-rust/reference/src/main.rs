use node115_rng_refill::{refill, State};
use rand_chacha::{ChaCha12Rng, ChaCha20Rng};
use rand_core::{RngCore, SeedableRng};
fn main() {
    let mut count = 0;
    let mut rejected = [0usize; 4];
    for seed_index in 0..16_u32 {
        for counter in [
            0,
            1,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX - 3,
            u64::MAX - 1,
        ] {
            for stream in [0, 1, 0xfedcba9876543210] {
                let mut seed = [0u8; 32];
                for (i, x) in seed.iter_mut().enumerate() {
                    *x = (i as u8).wrapping_mul(17).wrapping_add(seed_index as u8);
                }
                let mut key = [0u32; 8];
                for (i, x) in key.iter_mut().enumerate() {
                    *x = u32::from_le_bytes(seed[i * 4..i * 4 + 4].try_into().unwrap());
                }
                let mut state = State {
                    key,
                    tail: [
                        counter as u32,
                        (counter >> 32) as u32,
                        stream as u32,
                        (stream >> 32) as u32,
                    ],
                };
                let actual = refill(&mut state);
                let mut reference = ChaCha12Rng::from_seed(seed);
                reference.set_stream(stream);
                reference.set_word_pos(u128::from(counter) * 16);
                for (i, &word) in actual.iter().enumerate() {
                    assert_eq!(word, reference.next_u32(), "case {count} word {i}");
                }
                let next = counter.wrapping_add(4);
                assert_eq!(
                    state.tail,
                    [
                        next as u32,
                        (next >> 32) as u32,
                        stream as u32,
                        (stream >> 32) as u32
                    ]
                );
                assert_eq!(state.key, key);
                let mut c20 = ChaCha20Rng::from_seed(seed);
                c20.set_stream(stream);
                c20.set_word_pos(u128::from(counter) * 16);
                let mut wrong_counter = ChaCha12Rng::from_seed(seed);
                wrong_counter.set_stream(stream);
                wrong_counter.set_word_pos(u128::from(counter.wrapping_add(1)) * 16);
                let mut wrong_stream = ChaCha12Rng::from_seed(seed);
                wrong_stream.set_stream(stream ^ 1);
                wrong_stream.set_word_pos(u128::from(counter) * 16);
                seed[0] ^= 1;
                let mut wrong_key = ChaCha12Rng::from_seed(seed);
                wrong_key.set_stream(stream);
                wrong_key.set_word_pos(u128::from(counter) * 16);
                for (j, wrong) in [
                    c20.next_u32(),
                    wrong_counter.next_u32(),
                    wrong_stream.next_u32(),
                    wrong_key.next_u32(),
                ]
                .iter()
                .enumerate()
                {
                    if actual[0] != *wrong {
                        rejected[j] += 1;
                    }
                }
                count += 1;
            }
        }
    }
    assert_eq!(rejected, [count; 4]);
    println!("matched {count} cases / {} words; four altered references differed on {count}/{count} cases each",count*64);
}
