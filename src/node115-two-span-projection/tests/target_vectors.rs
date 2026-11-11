use node115_two_span_projection::project;

#[test]
fn static_target_relation_boundary_vectors() {
    let max = u64::MAX;
    let vectors = [
        ((10, 1_000, 8, 0), [1_000; 4]),
        ((10, 1_000, 3, 4), [1_240, 1_560, 1_000, 1_000]),
        ((10, 1_000, 8, 2), [1_640, 1_800, 1_000, 1_000]),
        ((10, 1_000, 8, 5), [1_640, 1_800, 1_000, 1_240]),
        ((10, 1_000, 18, 5), [1_640, 1_800, 1_000, 1_240]),
        ((10, 1_000, 28, 3), [2_440, 2_680, 1_000, 1_000]),
        ((10, max - 79, 1, 1), [0, 80, max - 79, max - 79]),
    ];

    for (input, expected) in vectors {
        assert_eq!(project(input.0, input.1, input.2, input.3), expected);
    }
}

#[test]
fn matches_the_branch_relation_for_u64_inputs() {
    // Independent transcription of the observed branch, normalization, and
    // wrapping multiply/add operations, without assigning source-level types.
    let mut state = 0x152e360_u64;
    for _ in 0..10_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let c = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let b = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let h = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let n = state;

        let expected = if n == 0 {
            [b; 4]
        } else {
            let a = if h >= c { h.wrapping_sub(c) } else { h };
            let remaining = c.wrapping_sub(a);
            let first_start = b.wrapping_add(80_u64.wrapping_mul(a));
            if n > remaining {
                [
                    first_start,
                    b.wrapping_add(80_u64.wrapping_mul(c)),
                    b,
                    b.wrapping_add(80_u64.wrapping_mul(n.wrapping_sub(remaining))),
                ]
            } else {
                [
                    first_start,
                    b.wrapping_add(80_u64.wrapping_mul(a.wrapping_add(n))),
                    b,
                    b,
                ]
            }
        };
        assert_eq!(project(c, b, h, n), expected);
    }
}
