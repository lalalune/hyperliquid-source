#![no_std]
//! Safe value/state relation of three node115 addition leaves, not their ABI.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Addition {
    pub words: [u64; 4],
    pub carry: u8,
}

/// Mutate the left operand and return a separate result copy plus carry-out.
pub fn add_with_carry(left: &mut [u64; 4], right: [u64; 4]) -> Addition {
    let mut carry = 0u128;
    for i in 0..4 {
        let sum = u128::from(left[i]) + u128::from(right[i]) + carry;
        left[i] = sum as u64;
        carry = sum >> 64;
    }
    Addition {
        words: *left,
        carry: carry as u8,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Guarded {
    pub count: usize,
    pub status: u64,
}

/// Safe API refusal outside our valid-storage domain; not a native error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountOutsideStorage;

/// Preserve inactive entries; discard arithmetic carry on the guarded method.
pub fn guarded_add(entries: &mut [[u64; 4]], count: usize) -> Result<Guarded, CountOutsideStorage> {
    if count > entries.len() {
        return Err(CountOutsideStorage);
    }
    if count < 2 {
        return Ok(Guarded { count, status: 44 });
    }
    let right = entries[count - 1];
    add_with_carry(&mut entries[count - 2], right);
    Ok(Guarded {
        count: count - 1,
        status: 0,
    })
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    mod fixture {
        include!("../../research/work-items/RE-004-limb-add-family-115/client_fixture.rs");
    }
    #[test]
    fn frozen_original_whole_leaves() {
        for line in
            include_str!("../../research/work-items/RE-004-limb-add-family-115/target-smoke.tsv")
                .lines()
        {
            let fields: std::vec::Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 11);
            let v: std::vec::Vec<u64> = fields[..10].iter().map(|s| s.parse().unwrap()).collect();
            let actual = fixture::observe(
                v[0] as usize,
                v[1] as usize,
                [v[2], v[3], v[4], v[5]],
                [v[6], v[7], v[8], v[9]],
            );
            assert_eq!(actual, fields[10], "input {:?}", v);
        }
    }
    #[test]
    fn safe_domain_refusal_preserves_storage() {
        let mut entries = [[7; 4]; 2];
        assert_eq!(
            super::guarded_add(&mut entries, 3),
            Err(super::CountOutsideStorage)
        );
        assert_eq!(entries, [[7; 4]; 2]);
    }
}
