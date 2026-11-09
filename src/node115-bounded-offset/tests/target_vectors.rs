use node115_bounded_offset::bounded_offset;

#[test]
fn static_target_relation_boundary_vectors() {
    let max = u64::MAX;
    let vectors = [
        ((0, 0, 0), (1, 0)),
        ((8, 3, 10), (0, 5)),
        ((8, 3, 5), (0, 4)),
        ((8, 8, 9), (0, 8)),
        ((8, 9, 20), (0, 7)),
        ((8, 3, 1), (0, 0)),
        ((0, 1, max), (0, max - 1)),
        ((max, max, max), (0, max - 1)),
        ((max, 0, max), (0, max - 1)),
        ((0, max, max), (0, 1)),
    ];

    for (input, expected) in vectors {
        assert_eq!(bounded_offset(input.0, input.1, input.2), expected);
    }
}

#[test]
fn matches_the_instruction_loop_for_u64_inputs() {
    // Independent transcription of the leaf's unsigned compare/shift/sub loop.
    let mut state = 0x115_u64;
    for _ in 0..10_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let capacity = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let head = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let length = state;

        let expected = if length == 0 {
            (1, 0)
        } else {
            let mut distance = if head < capacity { 0 } else { capacity };
            distance = distance.wrapping_sub(head).wrapping_add(capacity);
            if distance < length {
                (0, distance)
            } else {
                let mut remaining = length;
                let mut sum = 0_u64;
                while remaining > 1 {
                    let half = remaining >> 1;
                    sum = sum.wrapping_add(half);
                    remaining -= half;
                }
                (0, sum)
            }
        };
        assert_eq!(bounded_offset(capacity, head, length), expected);
    }
}
