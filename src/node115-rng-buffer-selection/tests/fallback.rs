use node115_rng_buffer_selection::{State, Step, begin};

fn selected_refill(state: &mut State) -> node115_rng_buffer_selection::RefillRequest<'_> {
    let epoch = state.observed_epoch;
    match begin(state, epoch) {
        Step::Refill(request) => request,
        Step::Word(_) => panic!("exhausted fixture returned a buffered word"),
        Step::Entropy(_) => panic!("fixture selected entropy instead of refill"),
    }
}

#[test]
fn fallback_composition_updates_only_the_refill_state_and_consumes_word_zero() {
    let mut key_state = [0u8; 48];
    for (index, byte) in key_state.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut state = State {
        cursor: 64,
        remaining: 512,
        base_budget: 768,
        observed_epoch: 9,
        key_state,
        buffer: [0xfeed_face; 64],
    };

    let returned = selected_refill(&mut state).complete_four_block_fallback();

    assert_eq!(returned, state.buffer[0]);
    assert_eq!(state.cursor, 1);
    assert_eq!(state.remaining, 256);
    assert_eq!(state.base_budget, 768);
    assert_eq!(state.observed_epoch, 9);
    assert_eq!(&state.key_state[..32], &key_state[..32]);
    let old_tail = [
        u32::from_le_bytes(key_state[32..36].try_into().unwrap()),
        u32::from_le_bytes(key_state[36..40].try_into().unwrap()),
        u32::from_le_bytes(key_state[40..44].try_into().unwrap()),
        u32::from_le_bytes(key_state[44..48].try_into().unwrap()),
    ];
    let old_counter = u64::from(old_tail[0]) | (u64::from(old_tail[1]) << 32);
    let next_counter = old_counter.wrapping_add(4);
    assert_eq!(state.key_state[32..36], (next_counter as u32).to_le_bytes());
    assert_eq!(
        state.key_state[36..40],
        ((next_counter >> 32) as u32).to_le_bytes()
    );
    assert_eq!(&state.key_state[40..48], &key_state[40..48]);
    assert_ne!(state.buffer, [0xfeed_face; 64]);
}

#[test]
fn fallback_matches_the_standalone_refill_contract() {
    let mut state = State {
        cursor: 64,
        remaining: 256,
        base_budget: 256,
        observed_epoch: 4,
        key_state: [0; 48],
        buffer: [0; 64],
    };
    let returned = selected_refill(&mut state).complete_four_block_fallback();
    assert_eq!(returned, 0x6a9a_f49b);
    assert_eq!(state.key_state[32..36], 4u32.to_le_bytes());
    assert_eq!(state.key_state[36..40], 0u32.to_le_bytes());
    assert_eq!(state.buffer[0], returned);
}
