//! Peer connection admission, greeting checks, and lifecycle manager matching
//! node #115 `node/src/connections.rs` (`0x2accee0..0x2ad0db0`, `0x2ad0db0..0x2ad4db7`).

use core::fmt;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Observed `"connection_checks"` timeout constant at `0x2acd08c -> .rodata 0x4593d0` (`5.0`s).
pub const CONNECTION_CHECKS_TIMEOUT_SECS: f64 = 5.0;

/// Observed `"handle_node_connection"` outer timeout constant at `0x2ace646 -> .rodata 0x4594a0`
/// (`10_000_000_000.0`s).
pub const HANDLE_NODE_CONNECTION_TIMEOUT_SECS: f64 = 10_000_000_000.0;

/// Exact diagnostic reasons emitted by `node/src/connections.rs` (`0x6055b4..0x605781`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionRejectReason {
    ChecksTimedOut,
    NoQuorumYet,
    CouldNotReadGreeting,
    FailedToVerifyPeer,
    PeerAlreadyConnected,
    MaxConnectionAgeReached,
}

impl ConnectionRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChecksTimedOut => "connection checks timed out",
            Self::NoQuorumYet => "closing gossip stream because no quorum yet",
            Self::CouldNotReadGreeting => "could not read tcp greeting",
            Self::FailedToVerifyPeer => "closing gossip stream because failed to verify peer",
            Self::PeerAlreadyConnected => "closing gossip stream because peer is already connected",
            Self::MaxConnectionAgeReached => "max connection age reached",
        }
    }
}

impl fmt::Display for ConnectionRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Active peer connection tracker enforcing node #115's quorum gate, peer
/// verification, duplicate-peer rejection, and max connection age eviction.
#[derive(Clone, Debug)]
pub struct ConnectionRegistry {
    active: BTreeMap<Ipv4Addr, Instant>,
    has_quorum: bool,
    max_connection_age: Duration,
}

impl ConnectionRegistry {
    pub fn new(has_quorum: bool, max_connection_age: Duration) -> Self {
        Self {
            active: BTreeMap::new(),
            has_quorum,
            max_connection_age,
        }
    }

    pub fn set_quorum(&mut self, has_quorum: bool) {
        self.has_quorum = has_quorum;
    }

    /// Run `connection_checks` admission for an incoming peer connection.
    pub fn admit_connection(
        &mut self,
        peer: Ipv4Addr,
        greeting_received: bool,
        peer_verified: bool,
        check_elapsed: Duration,
        now: Instant,
    ) -> Result<(), ConnectionRejectReason> {
        if check_elapsed > Duration::from_secs_f64(CONNECTION_CHECKS_TIMEOUT_SECS) {
            return Err(ConnectionRejectReason::ChecksTimedOut);
        }
        if !self.has_quorum {
            return Err(ConnectionRejectReason::NoQuorumYet);
        }
        if !greeting_received {
            return Err(ConnectionRejectReason::CouldNotReadGreeting);
        }
        if !peer_verified {
            return Err(ConnectionRejectReason::FailedToVerifyPeer);
        }
        if self.active.contains_key(&peer) {
            return Err(ConnectionRejectReason::PeerAlreadyConnected);
        }
        self.active.insert(peer, now);
        Ok(())
    }

    /// Evict connections whose age has reached `max_connection_age`, returning
    /// evicted peer IPs (`"max connection age reached"` -> `"dropping connection"`).
    pub fn evict_expired(&mut self, now: Instant) -> Vec<Ipv4Addr> {
        let mut expired = Vec::new();
        self.active.retain(|&ip, connected_at| {
            if now.saturating_duration_since(*connected_at) >= self.max_connection_age {
                expired.push(ip);
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn disconnect(&mut self, peer: Ipv4Addr) -> bool {
        self.active.remove(&peer).is_some()
    }

    pub fn is_connected(&self, peer: Ipv4Addr) -> bool {
        self.active.contains_key(&peer)
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}
