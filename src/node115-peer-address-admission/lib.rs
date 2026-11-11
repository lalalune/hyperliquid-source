//! Logical selected node115 peer-map lookup and listener IPv4 admission.
#![no_std]
extern crate alloc;
use alloc::collections::BTreeMap;

pub type PeerId = [u8; 20];
pub type Ipv4 = [u8; 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The listener's exact 127.0.0.1 branch bypasses the lookup.
    Loopback,
    Matched,
    Missing,
    Mismatched,
}

/// The supplied map is the logical projection of the owner protected by the
/// native reader lock; its population, freshness and identity origin are not
/// established by this operation. Native allocator and concurrency effects are
/// excluded. The exact loopback branch precedes every lookup.
pub fn admit(entries: &BTreeMap<PeerId, Ipv4>, identity: &PeerId, observed: Ipv4) -> Admission {
    if observed == [127, 0, 0, 1] {
        return Admission::Loopback;
    }
    match entries.get(identity) {
        None => Admission::Missing,
        Some(expected) if *expected == observed => Admission::Matched,
        Some(_) => Admission::Mismatched,
    }
}

/// The selected native producer uses a low presence byte followed by the
/// little-endian IPv4 DWORD. Payload bits for an absent result are inactive.
pub fn packed_present(ip: Ipv4) -> u64 {
    (u64::from(u32::from_le_bytes(ip)) << 8) | 1
}
