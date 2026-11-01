//! Safe ordered byte-copy projection of node #94 [0x3818d40, 0x3818dc4).
#![no_std]
#![forbid(unsafe_code)]

fn copy_block<const N: usize>(arena: &mut [u8], source: usize, destination: usize, reverse: bool) {
    let mut block = [0_u8; N];
    block.copy_from_slice(&arena[source..source + N]);
    if reverse {
        block.reverse();
    }
    arena[destination..destination + N].copy_from_slice(&block);
}

/// Apply the four observed load/store stages, including overlapping ranges.
///
/// Each range spans 52 bytes. Invalid or overflowing ranges return `None`
/// before any mutation. Otherwise `Some(destination)` projects the original
/// RAX destination pointer to an offset in this arena, not a raw pointer ABI.
/// Memory is ordinary initialized bytes, with no concurrent external mutation.
pub fn copy_record(arena: &mut [u8], source: usize, destination: usize) -> Option<usize> {
    let source_end = source.checked_add(52)?;
    let destination_end = destination.checked_add(52)?;
    if source_end > arena.len() || destination_end > arena.len() {
        return None;
    }
    copy_block::<4>(arena, source + 48, destination + 16, false);
    copy_block::<16>(arena, source + 32, destination, false);
    copy_block::<16>(arena, source + 16, destination + 20, true);
    copy_block::<16>(arena, source, destination + 36, true);
    Some(destination)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::copy_record;

    #[test]
    fn disjoint_layout_and_returned_offset() {
        let mut arena = core::array::from_fn::<_, 128, _>(|index| index as u8);
        assert_eq!(copy_record(&mut arena, 0, 64), Some(64));
        assert_eq!(&arena[64..84], &(32_u8..52).collect::<std::vec::Vec<_>>());
        assert_eq!(
            &arena[84..116],
            &(0_u8..32).rev().collect::<std::vec::Vec<_>>()
        );
        assert_eq!(arena[63], 63);
        assert_eq!(arena[116], 116);
    }

    #[test]
    fn in_place_reads_observe_prior_writes() {
        let mut arena = core::array::from_fn::<_, 52, _>(|index| index as u8);
        assert_eq!(copy_record(&mut arena, 0, 0), Some(0));
        assert_eq!(
            arena,
            [
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 31,
                30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42,
                41, 40, 39, 38, 37, 36, 35, 34, 33, 32,
            ]
        );
    }

    #[test]
    fn refusal_precedes_every_store() {
        let original = [0x93; 64];
        let mut arena = original;
        for (source, destination) in [(usize::MAX, 0), (0, usize::MAX), (13, 0), (0, 13)] {
            assert_eq!(copy_record(&mut arena, source, destination), None);
            assert_eq!(arena, original);
        }
        assert_eq!(copy_record(&mut arena[..51], 0, 0), None);
        assert_eq!(arena, original);
    }
}
