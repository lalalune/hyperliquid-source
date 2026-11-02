/// Bytes supplied by a caller that independently qualified the complete entry preimage.
///
/// The retained node #94 evidence proves BLAKE3 XOF use, but not the complete serialization
/// fed into it. The explicit constructor name keeps that boundary visible at call sites.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEntryBytes(Vec<u8>);

impl VerifiedEntryBytes {
    #[must_use]
    pub fn from_independently_verified(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatticeContribution {
    words: [u16; 1024],
}

impl LatticeContribution {
    #[must_use]
    pub fn from_entry(entry: &VerifiedEntryBytes) -> Self {
        let mut output = [0_u8; 2048];
        let mut reader = blake3::Hasher::new()
            .update(entry.as_bytes())
            .finalize_xof();
        reader.fill(&mut output);
        let words = core::array::from_fn(|index| {
            u16::from_be_bytes([output[index * 2], output[index * 2 + 1]])
        });
        Self { words }
    }

    #[must_use]
    pub const fn words(&self) -> &[u16; 1024] {
        &self.words
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatticeAccumulator {
    words: [u16; 1024],
    record_count: u64,
    byte_count: u64,
}

impl Default for LatticeAccumulator {
    fn default() -> Self {
        Self {
            words: [0; 1024],
            record_count: 0,
            byte_count: 0,
        }
    }
}

impl LatticeAccumulator {
    #[must_use]
    pub const fn from_parts(words: [u16; 1024], record_count: u64, byte_count: u64) -> Self {
        Self {
            words,
            record_count,
            byte_count,
        }
    }

    #[must_use]
    pub const fn words(&self) -> &[u16; 1024] {
        &self.words
    }

    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }

    pub fn add(&mut self, entry: &VerifiedEntryBytes) -> LatticeContribution {
        let contribution = LatticeContribution::from_entry(entry);
        for (word, addend) in self.words.iter_mut().zip(contribution.words) {
            *word = word.wrapping_add(addend);
        }
        self.record_count = self.record_count.saturating_add(1);
        self.byte_count = self.byte_count.saturating_add(entry_len(entry));
        contribution
    }

    pub fn subtract(&mut self, entry: &VerifiedEntryBytes) -> LatticeContribution {
        let contribution = LatticeContribution::from_entry(entry);
        for (word, subtrahend) in self.words.iter_mut().zip(contribution.words) {
            *word = word.wrapping_sub(subtrahend);
        }
        self.record_count = self.record_count.saturating_sub(1);
        self.byte_count = self.byte_count.saturating_sub(entry_len(entry));
        contribution
    }

    /// Apply the proven old-before-new replacement order.
    pub fn replace(
        &mut self,
        old: Option<&VerifiedEntryBytes>,
        new: &VerifiedEntryBytes,
    ) -> AccumulatorDelta {
        let before_record_count = self.record_count;
        let before_byte_count = self.byte_count;
        let removed = old.map(|entry| self.subtract(entry));
        let added = self.add(new);
        AccumulatorDelta {
            before_record_count,
            before_byte_count,
            after_record_count: self.record_count,
            after_byte_count: self.byte_count,
            removed,
            added,
        }
    }
}

fn entry_len(entry: &VerifiedEntryBytes) -> u64 {
    u64::try_from(entry.as_bytes().len()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccumulatorDelta {
    pub before_record_count: u64,
    pub before_byte_count: u64,
    pub after_record_count: u64,
    pub after_byte_count: u64,
    pub removed: Option<LatticeContribution>,
    pub added: LatticeContribution,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(bytes: &[u8]) -> VerifiedEntryBytes {
        VerifiedEntryBytes::from_independently_verified(bytes.to_vec())
    }

    #[test]
    fn official_blake3_known_answer_vectors() {
        assert_eq!(
            hex(blake3::hash(b"").as_bytes()),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hex(blake3::hash(b"abc").as_bytes()),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn xof_is_2048_bytes_interpreted_as_big_endian_words() {
        let contribution = LatticeContribution::from_entry(&entry(b""));
        assert_eq!(contribution.words()[0], 0xaf13);
        assert_eq!(contribution.words()[1], 0x49b9);
        assert_ne!(contribution.words()[0], 0x13af);
        assert_eq!(contribution.words().len(), 1024);
    }

    #[test]
    fn insert_replace_remove_and_multiple_entries() {
        let first = entry(b"first independently verified entry");
        let second = entry(b"second independently verified entry");
        let mut accumulator = LatticeAccumulator::default();

        let first_contribution = accumulator.add(&first);
        assert_eq!(accumulator.words(), first_contribution.words());
        assert_eq!(accumulator.record_count(), 1);
        assert_eq!(accumulator.byte_count(), first.as_bytes().len() as u64);

        let delta = accumulator.replace(Some(&first), &second);
        let second_contribution = LatticeContribution::from_entry(&second);
        assert_eq!(accumulator.words(), second_contribution.words());
        assert_eq!(accumulator.record_count(), 1);
        assert_eq!(accumulator.byte_count(), second.as_bytes().len() as u64);
        assert_eq!(delta.removed, Some(first_contribution));
        assert_eq!(delta.added, second_contribution);

        accumulator.add(&first);
        let combined = accumulator.clone();
        assert_eq!(combined.record_count(), 2);
        accumulator.subtract(&first);
        assert_eq!(accumulator.words(), second_contribution.words());
    }

    #[test]
    fn add_then_subtract_restores_zero_deterministically() {
        let value = entry(b"deterministic");
        let mut first = LatticeAccumulator::default();
        let mut second = LatticeAccumulator::default();
        assert_eq!(first.add(&value), second.add(&value));
        first.subtract(&value);
        second.subtract(&value);
        assert_eq!(first, LatticeAccumulator::default());
        assert_eq!(first, second);
    }

    #[test]
    fn counters_saturate_in_both_directions() {
        let value = entry(b"1234");
        let mut accumulator = LatticeAccumulator::from_parts([0; 1024], u64::MAX, u64::MAX);
        accumulator.add(&value);
        assert_eq!(accumulator.record_count(), u64::MAX);
        assert_eq!(accumulator.byte_count(), u64::MAX);

        let mut empty = LatticeAccumulator::default();
        empty.subtract(&value);
        assert_eq!(empty.record_count(), 0);
        assert_eq!(empty.byte_count(), 0);
    }

    #[test]
    fn words_wrap_on_overflow_and_underflow() {
        let value = entry(b"wrap");
        let contribution = LatticeContribution::from_entry(&value);
        let overflow_words = core::array::from_fn(|index| {
            u16::MAX
                .wrapping_sub(contribution.words()[index])
                .wrapping_add(1)
        });
        let mut overflow = LatticeAccumulator::from_parts(overflow_words, 0, 0);
        overflow.add(&value);
        assert_eq!(overflow.words(), &[0; 1024]);

        let mut underflow = LatticeAccumulator::default();
        underflow.subtract(&value);
        for (actual, expected) in underflow.words().iter().zip(contribution.words()) {
            assert_eq!(*actual, 0_u16.wrapping_sub(*expected));
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
