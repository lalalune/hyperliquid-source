//! Node #115 iterator records passed from newtype serializers to their inner collectors.

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

/// Defined words of the argument to the inner collector. The ring form has
/// four trailing padding words in the captured layout, which are never read here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceInput {
    Tree([u64; 9]),
    Ring([u64; 5]),
}

/// Produce the collector input for a sequence newtype. Element size is the
/// recovered stride of the selected forwarder, in bytes.
pub fn sequence_input(
    name: &[u8],
    value: [u64; 4],
    element_size: u64,
) -> Result<SequenceInput, &'static str> {
    if name == b"_ExtStruct" {
        return Err("expected tuple");
    }
    let [tag_or_capacity, pointer, height_or_head, length] = value;
    if tag_or_capacity == 1 << 63 {
        let has_root = u64::from(pointer != 0);
        let count = if pointer == 0 { 0 } else { length };
        return Ok(SequenceInput::Tree([
            has_root,
            0,
            pointer,
            height_or_head,
            has_root,
            0,
            pointer,
            height_or_head,
            count,
        ]));
    }
    let slices = ring_slices(
        pointer,
        tag_or_capacity,
        height_or_head,
        length,
        element_size,
    );
    Ok(SequenceInput::Ring([
        2,
        slices.first_start,
        slices.first_end,
        slices.second_start,
        slices.second_end,
    ]))
}

#[cfg(test)]
mod tests {
    use super::{ring_slices, sequence_input, RingSlices, SequenceInput};
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
    fn matches_all_frozen_sequence_inputs() {
        let sizes: BTreeMap<_, _> = BODIES
            .lines()
            .skip(1)
            .filter_map(|line| {
                let row = columns(line);
                (row[4] == "seq").then(|| (row[0], hex(row[6])))
            })
            .collect();
        let mut counts = BTreeMap::new();
        let mut arms = [0, 0];
        for line in CASES.lines().skip(1) {
            let row = columns(line);
            let Some(&size) = sizes.get(row[0]) else {
                continue;
            };
            let name: Vec<_> = row[3]
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let value = words(row[6]).try_into().unwrap();
            let expected = words(row[7]);
            let record = sequence_input(&name, value, size).unwrap();
            let actual: &[u64] = match &record {
                SequenceInput::Tree(fields) => {
                    arms[0] += 1;
                    fields
                }
                SequenceInput::Ring(fields) => {
                    arms[1] += 1;
                    fields
                }
            };
            assert_eq!(actual, expected, "body {} case {}", row[0], row[1]);
            *counts.entry(row[0]).or_insert(0) += 1;
        }
        assert_eq!(arms, [725, 725]);
        assert_eq!(counts.len(), 29);
    }

    #[test]
    fn reserved_name_precedes_representation_selection() {
        for tag in [1 << 63, 16] {
            let value = [tag, 0, 0, 0];
            assert_eq!(
                sequence_input(b"_ExtStruct", value, 32),
                Err("expected tuple")
            );
            assert!(sequence_input(b"_ExtStructX", value, 32).is_ok());
            assert!(sequence_input(b"_extStruct", value, 32).is_ok());
        }
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
