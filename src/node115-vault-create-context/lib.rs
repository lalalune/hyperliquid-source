//! Concrete context provenance on the 2bdd3b0 -> 44ae810 creation path.
//! Earlier validation and address derivation must already have succeeded.
//! Original identity is an entry argument; cryptographic signer provenance
//! and the semantics of later vault effects are not inferred here.
#[path = "../node115-vault-identity-guards/src/lib.rs"]
pub mod existing_guards;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handoff {
    pub raw_mode: u64,
    pub policy_byte: u8,
    /// Context+0x8c: output of the earlier 0x46dba10 address helper.
    pub lookup_identity: [u8; 20],
    /// Context+0xa0: original identity supplied to 0x2bdd3b0 in RDX.
    pub retained_identity: [u8; 20],
    /// RDX at 0x44ae810: the same original identity, not the derived address.
    pub incoming_identity: [u8; 20],
}

/// Reconstructs only the observed successful creation-wrapper handoff.
/// It does not decide whether earlier validation authorizes reaching this point.
pub fn after_wrapper_checks(original_identity: [u8; 20], derived_identity: [u8; 20]) -> Handoff {
    Handoff {
        raw_mode: 0,
        policy_byte: 1,
        lookup_identity: derived_identity,
        retained_identity: original_identity,
        incoming_identity: original_identity,
    }
}
impl Handoff {
    /// Writes only the proven fields. All unrelated context bytes survive.
    pub fn write_proven_context_fields(&self, context: &mut [u8; 0xb8]) {
        context[..8].copy_from_slice(&self.raw_mode.to_le_bytes());
        context[0x8c..0xa0].copy_from_slice(&self.lookup_identity);
        context[0xa0..0xb4].copy_from_slice(&self.retained_identity);
        // 0x44ae57f writes dword 0x100 at context+0xb4.
        context[0xb4] = 0;
        context[0xb5] = self.policy_byte;
        context[0xb6..0xb8].fill(0);
    }
    pub fn prelude(&self) -> existing_guards::PreludeResult {
        existing_guards::evaluate_prelude(
            self.raw_mode,
            self.policy_byte,
            &self.incoming_identity,
            &self.retained_identity,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_single_bit_identity_differences_keep_roles_separate() {
        for bit in 0..160 {
            let mut derived = [0; 20];
            derived[bit / 8] = 1 << (bit % 8);
            let h = after_wrapper_checks([0; 20], derived);
            assert_eq!(h.lookup_identity, derived);
            assert_eq!(h.retained_identity, [0; 20]);
            assert_eq!(h.incoming_identity, [0; 20]);
            assert_eq!((h.raw_mode, h.policy_byte), (0, 1));
            assert_eq!(
                h.prelude(),
                existing_guards::PreludeResult::ContinueToNextStage
            );
        }
    }
    #[test]
    fn fields_land_at_original_offsets_without_zero_filling_opaque_state() {
        let original = std::array::from_fn(|i| i as u8);
        let derived = std::array::from_fn(|i| 200 + i as u8);
        let h = after_wrapper_checks(original, derived);
        let mut bytes = [0xaa; 0xb8];
        h.write_proven_context_fields(&mut bytes);
        assert_eq!(&bytes[..8], &[0; 8]);
        assert_eq!(&bytes[8..0x8c], &[0xaa; 0x84]);
        assert_eq!(&bytes[0x8c..0xa0], &derived);
        assert_eq!(&bytes[0xa0..0xb4], &original);
        assert_eq!(&bytes[0xb4..0xb8], &[0, 1, 0, 0]);
        assert_eq!(h.incoming_identity, original);
    }
    #[test]
    fn successful_prelude_is_not_complete_vault_acceptance() {
        let h = after_wrapper_checks([0xff; 20], [0; 20]);
        assert_eq!(
            h.prelude(),
            existing_guards::PreludeResult::ContinueToNextStage
        );
        // Counterfactual fixtures distinguish the existing guard modes. They
        // are not claimed reachable through this creation path.
        let mut changed = h.clone();
        changed.raw_mode = 1;
        changed.incoming_identity[19] ^= 1;
        assert!(matches!(
            changed.prelude(),
            existing_guards::PreludeResult::Reject { reason: 0x16, .. }
        ));
        changed.raw_mode = 0;
        changed.policy_byte = 0;
        assert!(matches!(
            changed.prelude(),
            existing_guards::PreludeResult::Reject { reason: 0x17, .. }
        ));
        assert_eq!(h.lookup_identity, [0; 20]);
    }
}
