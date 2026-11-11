//! Bounded node #115 model for ring-buffer slices passed to sequence serializers.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingSlices {
    pub first_start: u64,
    pub first_end: u64,
    pub second_start: u64,
    pub second_end: u64,
}

/// Reconstruct the two physical slices of the ring buffer.
///
/// As observed in the #115 sequence forwarders, `head` is reduced by capacity
/// once when it is at least capacity. Empty sequences point all four boundaries
/// at the buffer. For non-empty sequences, the logical range is split only when
/// its length exceeds the space remaining from the normalized head to the end.
pub fn ring_slices(
    buffer: u64,
    capacity: u64,
    head: u64,
    length: u64,
    element_size: u64,
) -> RingSlices {
    let physical_head = if head >= capacity {
        head.wrapping_sub(capacity)
    } else {
        head
    };
    let first_start = buffer.wrapping_add(physical_head.wrapping_mul(element_size));

    if length == 0 {
        return RingSlices {
            first_start: buffer,
            first_end: buffer,
            second_start: buffer,
            second_end: buffer,
        };
    }

    let room = capacity.wrapping_sub(physical_head);
    let first_end = if length > room {
        buffer.wrapping_add(capacity.wrapping_mul(element_size))
    } else {
        buffer.wrapping_add(
            physical_head
                .wrapping_add(length)
                .wrapping_mul(element_size),
        )
    };
    let second_end = if length > room {
        buffer.wrapping_add(length.wrapping_sub(room).wrapping_mul(element_size))
    } else {
        buffer
    };

    RingSlices {
        first_start,
        first_end,
        second_start: buffer,
        second_end,
    }
}

#[cfg(test)]
mod tests {
    use super::{ring_slices, RingSlices};
    use std::collections::BTreeMap;

    const CASES: &str = include_str!(
        "../../../research/work-items/serialization-rmp-newtype-forward-115/cases-sample.tsv"
    );
    const BODIES: &str = include_str!(
        "../../../research/work-items/serialization-rmp-newtype-forward-115/bodies.tsv"
    );

    fn hex(value: &str) -> u64 {
        u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap()
    }

    fn words(value: &str) -> Vec<u64> {
        value.split(',').map(hex).collect()
    }

    fn columns(line: &str) -> Vec<&str> {
        line.split('\t').collect()
    }

    #[test]
    fn matches_recorded_ring_case_arguments() {
        let mut sizes = BTreeMap::new();
        for line in BODIES.lines().skip(1) {
            let c = columns(line);
            if c[4] == "seq" {
                sizes.insert(c[0], hex(c[6]));
            }
        }

        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let c = columns(line);
            if !c[2].starts_with("ring-") {
                continue;
            }
            let value = words(c[6]);
            let expected = words(c[7]);
            assert_eq!(expected[0], 2, "case {} tag", c[1]);
            let got = ring_slices(value[1], value[0], value[2], value[3], sizes[c[0]]);
            assert_eq!(
                [
                    got.first_start,
                    got.first_end,
                    got.second_start,
                    got.second_end
                ],
                [expected[1], expected[2], expected[3], expected[4]],
                "body {} case {} ({})",
                c[0],
                c[1],
                c[2]
            );
            checked += 1;
        }
        assert_eq!(checked, 725);
    }

    #[test]
    fn empty_ring_points_both_slices_at_the_buffer() {
        assert_eq!(
            ring_slices(0x1000, 16, 9, 0, 0x20),
            RingSlices {
                first_start: 0x1000,
                first_end: 0x1000,
                second_start: 0x1000,
                second_end: 0x1000,
            }
        );
    }
}
