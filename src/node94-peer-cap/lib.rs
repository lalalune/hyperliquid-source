//! Selected flagged-path peer-cap projection, not complete peer admission.
#![no_std]
#![forbid(unsafe_code)]

pub fn peer_limit(option: Option<u64>) -> (u64, bool) {
    match option {
        None => (8, false),
        Some(value) => {
            let limit = value.clamp(8, 100);
            (limit, limit != value)
        }
    }
}

/// Raw bit-0 NodeIp projection; concrete original enum layout remains unproved.
pub fn key(tag: u8, ip: u32) -> u32 {
    if tag & 1 != 0 {
        0x7f000001
    } else {
        ip
    }
}

pub fn counted_peers(peers: &[(u8, u32)], allowed: &[u32]) -> u64 {
    peers
        .iter()
        .filter(|&&(tag, ip)| !allowed.contains(&key(tag, ip)))
        .count() as u64
}

/// Return the measured intermediate low-byte code. Code 3 has a further,
/// unresolved step in the native caller and does not prove final admission.
pub fn cap_code(peers: &[(u8, u32)], allowed: &[u32], limit: u64, incoming: (u8, u32)) -> u8 {
    let count = counted_peers(peers, allowed);
    if count < limit || allowed.contains(&key(incoming.0, incoming.1)) {
        3
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limit_clamps_only_supplied_values() {
        assert_eq!(peer_limit(None), (8, false));
        assert_eq!(peer_limit(Some(1)), (8, true));
        assert_eq!(peer_limit(Some(100)), (100, false));
    }
    #[test]
    fn capacity_equality_and_allowlist_exception() {
        let peers = [(0, 1), (0, 2)];
        assert_eq!(cap_code(&peers, &[], 2, (0, 3)), 0);
        assert_eq!(cap_code(&peers, &[0x7f000001], 2, (3, 99)), 3);
        assert_eq!(counted_peers(&[(3, 0), (0, 1)], &[0x7f000001]), 1);
    }
}
