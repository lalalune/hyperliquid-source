use node115_rng_buffer_selection::{begin, State, Step};
use rand_chacha::{ChaCha12Rng, ChaCha20Rng};
use rand_core::{RngCore, SeedableRng};

fn key_state(seed: &[u8; 32], counter: u64, stream: u64) -> [u8; 48] {
    let mut out = [0; 48];
    out[..32].copy_from_slice(seed);
    out[32..36].copy_from_slice(&(counter as u32).to_le_bytes());
    out[36..40].copy_from_slice(&((counter >> 32) as u32).to_le_bytes());
    out[40..44].copy_from_slice(&(stream as u32).to_le_bytes());
    out[44..48].copy_from_slice(&((stream >> 32) as u32).to_le_bytes());
    out
}

fn first_word(seed: [u8; 32], counter: u64, stream: u64, rounds: u32) -> u32 {
    if rounds == 12 {
        let mut rng = ChaCha12Rng::from_seed(seed);
        rng.set_stream(stream);
        rng.set_word_pos(u128::from(counter) * 16);
        rng.next_u32()
    } else {
        let mut rng = ChaCha20Rng::from_seed(seed);
        rng.set_stream(stream);
        rng.set_word_pos(u128::from(counter) * 16);
        rng.next_u32()
    }
}

fn main() {
    let counters = [
        0,
        1,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX - 3,
        u64::MAX - 1,
    ];
    let streams = [0, 1, 0xfedc_ba98_7654_3210];
    let mut cases = 0usize;
    let mut rejected = [0usize; 4];

    for seed_index in 0..16_u32 {
        for counter in counters {
            for stream in streams {
                let mut seed = [0u8; 32];
                for (index, byte) in seed.iter_mut().enumerate() {
                    *byte = (index as u8)
                        .wrapping_mul(17)
                        .wrapping_add(seed_index as u8);
                }
                let original_state = key_state(&seed, counter, stream);
                let mut policy = State {
                    cursor: 64,
                    remaining: 256,
                    base_budget: 512,
                    observed_epoch: 17,
                    key_state: original_state,
                    buffer: [0xa5a5_a5a5; 64],
                };
                let returned = match begin(&mut policy, 17) {
                    Step::Refill(request) => request.complete_four_block_fallback(),
                    Step::Word(_) => panic!("exhausted buffer returned a word"),
                    Step::Entropy(_) => panic!("eligible refill selected entropy"),
                };

                let mut reference = ChaCha12Rng::from_seed(seed);
                reference.set_stream(stream);
                reference.set_word_pos(u128::from(counter) * 16);
                assert_eq!(returned, reference.next_u32());
                for word in &policy.buffer[1..] {
                    assert_eq!(*word, reference.next_u32());
                }
                let next = counter.wrapping_add(4);
                assert_eq!(policy.key_state, key_state(&seed, next, stream));
                assert_eq!(policy.cursor, 1);
                assert_eq!(policy.remaining, 0);
                assert_eq!(policy.base_budget, 512);
                assert_eq!(policy.observed_epoch, 17);

                let altered = [
                    first_word(seed, counter, stream, 20),
                    first_word(seed, counter.wrapping_add(1), stream, 12),
                    first_word(seed, counter, stream ^ 1, 12),
                    {
                        let mut wrong_seed = seed;
                        wrong_seed[0] ^= 1;
                        first_word(wrong_seed, counter, stream, 12)
                    },
                ];
                for (index, value) in altered.into_iter().enumerate() {
                    if returned != value {
                        rejected[index] += 1;
                    }
                }
                cases += 1;
            }
        }
    }

    assert_eq!(cases, 288);
    assert_eq!(rejected, [cases; 4]);
    println!(
        "{{\"cases\":{cases},\"words\":{},\"wrong_rounds_detected\":{},\"wrong_counter_detected\":{},\"wrong_stream_detected\":{},\"wrong_key_detected\":{},\"captured_target_executed\":false}}",
        cases * 64,
        rejected[0],
        rejected[1],
        rejected[2],
        rejected[3]
    );
}
