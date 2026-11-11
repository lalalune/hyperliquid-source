//! Pure model of the node #115 leaf at VA `0x2d55b30`.
//!
//! The nine output qwords and wrapping arithmetic follow the complete,
//! digest-bound instruction record in `research/work-items/RE-001-node115-ring-span`.
//! Field names and higher-level ownership remain unknown.

/// Compute the exact nine qwords written by the observed leaf for four raw
/// input qwords `(a, b, c, d)`. Address arithmetic wraps modulo 2^64.
///
/// This models values only. It does not dereference pointers or validate memory,
/// allocation geometry, concurrent mutation, or native fault behavior.
pub fn descriptor([a, b, c, d]: [u64; 4]) -> [u64; 9] {
    const SENTINEL: u64 = 1 << 63;
    const STRIDE: u64 = 48;
    const TAG: u64 = 2;

    if a == SENTINEL {
        let present = u64::from(b != 0);
        return [
            present,
            0,
            b,
            c,
            present,
            0,
            b,
            c,
            if present != 0 { d } else { 0 },
        ];
    }

    let (start, end, residual) = if d == 0 {
        (0, 0, 0)
    } else {
        let start = c.wrapping_sub(if c >= a { a } else { 0 });
        let room = a.wrapping_sub(start);
        if d > room {
            (start, a, d.wrapping_sub(room))
        } else {
            (start, start.wrapping_add(d), 0)
        }
    };
    let pointer = |index: u64| b.wrapping_add(index.wrapping_mul(STRIDE));
    let end_ptr = pointer(end);
    [
        TAG,
        pointer(start),
        end_ptr,
        b,
        pointer(residual),
        0,
        end_ptr,
        b,
        residual,
    ]
}

#[cfg(test)]
mod tests {
    use super::descriptor;

    fn words<const N: usize>(text: &str) -> [u64; N] {
        text.split(',')
            .map(|word| word.parse().expect("valid decimal qword"))
            .collect::<Vec<_>>()
            .try_into()
            .expect("expected number of qwords")
    }

    #[test]
    fn matches_instruction_derived_vectors() {
        let vectors = include_str!("../vectors.tsv");
        let mut count = 0;
        for row in vectors.lines().filter(|line| !line.starts_with('#')) {
            let mut fields = row.split('\t');
            let case = fields.next().expect("case name");
            let input = words(fields.next().expect("input qwords"));
            let expected = words(fields.next().expect("output qwords"));
            assert!(fields.next().is_none(), "extra columns in {case}");
            assert_eq!(descriptor(input), expected, "case={case}");
            count += 1;
        }
        assert_eq!(count, 14);
    }

    #[test]
    fn ring_spans_enumerate_positions_for_valid_geometry() {
        for capacity in 1u64..=16 {
            for head in 0..2 * capacity {
                for count in 0..=capacity {
                    let base = 4096u64;
                    let out = descriptor([capacity, base, head, count]);
                    let first = (out[1] - base) / 48;
                    let first_end = (out[2] - base) / 48;
                    let second = (out[3] - base) / 48;
                    let second_end = (out[4] - base) / 48;
                    let positions: Vec<_> = (first..first_end).chain(second..second_end).collect();
                    let expected: Vec<_> = (0..count).map(|n| (head + n) % capacity).collect();
                    assert_eq!(
                        positions, expected,
                        "capacity={capacity}, head={head}, count={count}"
                    );
                    assert_eq!(out[2], out[6]);
                    assert_eq!(out[3], out[7]);
                    assert_eq!(out[8], second_end - second);
                }
            }
        }
    }

    #[test]
    fn head_reduction_is_only_one_subtraction() {
        let out = descriptor([8, 4096, 17, 1]);
        assert_eq!(out[1], 4096 + 9 * 48);
    }
}
