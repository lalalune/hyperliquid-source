#![no_std]
#![forbid(unsafe_code)]

/// The observed scalar value relation; this API is not the original pointer ABI.
pub const fn tagged_count(tag: u64, left: u64, right: u64, cap: u64) -> u64 {
    let base = if tag == 0 {
        right
    } else if tag as u32 == 1 {
        left.saturating_sub(right)
    } else {
        0
    };
    if base < cap { base } else { cap }
}

#[cfg(test)]
mod tests {
    use super::tagged_count;

    #[test]
    fn frozen_instruction_derived_boundaries() {
        let mut count = 0;
        for line in include_str!("../../research/work-items/RE-001-node115-tagged-count/vectors.tsv").lines() {
            let mut fields = line.split('\t').map(|x| x.parse::<u64>().unwrap());
            let tag = fields.next().unwrap();
            let left = fields.next().unwrap();
            let right = fields.next().unwrap();
            let cap = fields.next().unwrap();
            let expected = fields.next().unwrap();
            assert!(fields.next().is_none());
            assert_eq!(tagged_count(tag, left, right, cap), expected);
            count += 1;
        }
        assert_eq!(count, 2058);
    }
}
