//! Lock-ordering diagnostics grounded in node #115 `base/src/lock_id.rs`
//! (`CodeLocation` 8x 221 B, `LockId` 4x 224 B, `LockLocation` 8x 221 B,
//! `LockOrderWitness` 4x 221 B, `LockOrderingViolation` 4x 165 B).

/// Source location recorded on lock acquisition (`0x1500880`, `0x1552430`, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodeLocation {
    pub fln: &'static str,
    pub line: u32,
}

/// Lock identifier with deadlock-detection toggle (`0x1544000`, `0x29af7e0`, etc.).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LockId {
    pub inner: String,
    pub deadlock_detection: bool,
}

/// Paired lock identifier and acquisition call site (`0x15440e0`, `0x1552350`, etc.).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LockLocation {
    pub id: LockId,
    pub call_location: CodeLocation,
}

/// Witness recording a previously observed `a -> b` lock acquisition edge (`0x15527d0`, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LockOrderWitness {
    pub a_lock_code_location: CodeLocation,
    pub b_lock_code_location: CodeLocation,
}

/// Lock-ordering cycle diagnostic (`0x15441c0`, `0x29af630`, `0x4773220`, `0x4f0dc00`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockOrderingViolation {
    pub reverse_edge: (LockId, LockId),
    pub reverse_witness: LockOrderWitness,
    pub lock_a: LockLocation,
    pub lock_b: LockLocation,
}
