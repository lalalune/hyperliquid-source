//! Firewall IP set diffing, reachability check, and visor time-lock paths matching
//! node #115 `node/src/firewall_ips.rs` (`0x4d56d10`) and `node/src/visor_time_lock.rs`
//! (`0x5a69e60`, `0x5a35f50`).

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Observed reachability check failure message at `.rodata 0x605d88`.
pub const UNREACHABLE_PEERS_MSG: &str = "Unreachable peers were found. Do not run validator with current IP until all peers have added it to their firewalls.";

/// Observed visor time-lock paths at `.rodata 0x93ad97..0x93adf5`.
pub const VISOR_TIME_LOCK_DIR: &str = "visor_time_lock";
pub const PUBLISHER_VISOR_TIME_LOCK_DIR: &str = "publisher_visor_time_lock";
pub const VISOR_STAGING_NOT_READY: &str = "visor_staging_NOT_READY";

/// Asymmetric difference between ABCI validator IPs and active firewall allowlist,
/// matching `.rodata 0x439ec6` (`abci_minus_firewall`, `firewall_minus_abci`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirewallDiff {
    pub abci_minus_firewall: BTreeSet<Ipv4Addr>,
    pub firewall_minus_abci: BTreeSet<Ipv4Addr>,
}

/// Firewall allowlist manager.
#[derive(Clone, Debug, Default)]
pub struct FirewallIps {
    allowed: BTreeSet<Ipv4Addr>,
}

impl FirewallIps {
    pub fn new(initial: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        Self {
            allowed: initial.into_iter().collect(),
        }
    }

    pub fn is_allowed(&self, ip: Ipv4Addr) -> bool {
        self.allowed.contains(&ip)
    }

    pub fn diff_against_abci(&self, abci_ips: &BTreeSet<Ipv4Addr>) -> FirewallDiff {
        FirewallDiff {
            abci_minus_firewall: abci_ips.difference(&self.allowed).copied().collect(),
            firewall_minus_abci: self.allowed.difference(abci_ips).copied().collect(),
        }
    }

    pub fn sync_to_abci(&mut self, abci_ips: &BTreeSet<Ipv4Addr>) -> FirewallDiff {
        let diff = self.diff_against_abci(abci_ips);
        self.allowed = abci_ips.clone();
        diff
    }

    pub fn allowed(&self) -> &BTreeSet<Ipv4Addr> {
        &self.allowed
    }
}

/// Format reachability validation result matching `.rodata 0x605d88`.
pub fn check_peer_reachability(unreachable: &[Ipv4Addr]) -> Result<(), String> {
    if unreachable.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{UNREACHABLE_PEERS_MSG} unreachable addresses: {unreachable:?}"
        ))
    }
}
