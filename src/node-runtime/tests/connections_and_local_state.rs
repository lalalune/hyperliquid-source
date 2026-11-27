use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use net_utils::{GossipStatus, Hardfork};
use node_runtime::{
    APPLYING_HARDFORK_MSG, CONNECTION_CHECKS_TIMEOUT_SECS, ConnectionRegistry,
    ConnectionRejectReason, HANDLE_NODE_CONNECTION_TIMEOUT_SECS, INITIALIZING_WITH_LOCAL_STATE_MSG,
    INSUFFICIENT_RPC_STATUSES_MSG, LOCAL_HEIGHT_STALE_HARDFORK_MSG,
    LOCAL_HEIGHT_TOO_FAR_BEHIND_MSG, LocalAbciSnapshot, LocalStateDecision, MAX_LOCAL_HEIGHT_LAG,
    MIN_VALID_RPC_STATUSES, UPGRADE_ROUND_WINDOW, evaluate_local_abci_state,
};

#[test]
fn connection_registry_enforces_node115_checks_and_max_age() {
    assert!((CONNECTION_CHECKS_TIMEOUT_SECS - 5.0).abs() < f64::EPSILON);
    assert!((HANDLE_NODE_CONNECTION_TIMEOUT_SECS - 10_000_000_000.0).abs() < f64::EPSILON);

    let now = Instant::now();
    let peer = Ipv4Addr::new(10, 0, 0, 5);
    let mut reg = ConnectionRegistry::new(false, Duration::from_secs(60));

    // Timeout (> 5.0s) triggers before other checks
    assert_eq!(
        reg.admit_connection(peer, true, true, Duration::from_millis(5001), now),
        Err(ConnectionRejectReason::ChecksTimedOut)
    );
    assert_eq!(
        ConnectionRejectReason::ChecksTimedOut.as_str(),
        "connection checks timed out"
    );

    // No quorum gate
    assert_eq!(
        reg.admit_connection(peer, true, true, Duration::from_millis(10), now),
        Err(ConnectionRejectReason::NoQuorumYet)
    );
    reg.set_quorum(true);

    // Missing greeting / failed verification
    assert_eq!(
        reg.admit_connection(peer, false, true, Duration::from_millis(10), now),
        Err(ConnectionRejectReason::CouldNotReadGreeting)
    );
    assert_eq!(
        reg.admit_connection(peer, true, false, Duration::from_millis(10), now),
        Err(ConnectionRejectReason::FailedToVerifyPeer)
    );

    // Admitted cleanly, then duplicate rejected
    reg.admit_connection(peer, true, true, Duration::from_secs(5), now)
        .unwrap();
    assert!(reg.is_connected(peer));
    assert_eq!(reg.len(), 1);
    assert_eq!(
        reg.admit_connection(peer, true, true, Duration::from_millis(1), now),
        Err(ConnectionRejectReason::PeerAlreadyConnected)
    );

    // Age eviction at >= max_connection_age
    assert!(reg.evict_expired(now + Duration::from_secs(59)).is_empty());
    assert_eq!(
        reg.evict_expired(now + Duration::from_secs(60)),
        vec![peer]
    );
    assert!(reg.is_empty());
}

#[test]
fn local_abci_state_matches_exact_node115_boundaries() {
    assert_eq!(MIN_VALID_RPC_STATUSES, 2);
    assert_eq!(MAX_LOCAL_HEIGHT_LAG, 20_000);
    assert_eq!(UPGRADE_ROUND_WINDOW, 400);

    let hf = Hardfork {
        version: 4,
        round: 1000,
    };
    let status_a = GossipStatus {
        hardfork_height: 50_000,
        latest_height: 100_000,
        hardfork: hf,
        latest_consensus_round: Some(1399),
    };
    let status_b = GossipStatus {
        hardfork_height: 50_000,
        latest_height: 99_990,
        hardfork: hf,
        latest_consensus_round: Some(1350),
    };

    // Fewer than 2 statuses -> InsufficientRpcStatuses
    let fresh_local = LocalAbciSnapshot {
        height: 80_001,
        hardfork: hf,
        frozen_for_upgrade: false,
    };
    let d0 = evaluate_local_abci_state(fresh_local, &[status_a]);
    assert_eq!(d0, LocalStateDecision::InsufficientRpcStatuses);
    assert_eq!(d0.diagnostic_msg(), INSUFFICIENT_RPC_STATUSES_MSG);

    // Exact 20_000 lag boundary (0x2add488..0x2add4ad: local + 20_000 <= remote_latest_height)
    let at_lag_boundary = LocalAbciSnapshot {
        height: 80_000,
        hardfork: hf,
        frozen_for_upgrade: false,
    };
    let d1 = evaluate_local_abci_state(at_lag_boundary, &[status_a, status_b]);
    assert_eq!(d1, LocalStateDecision::StaleTooFarBehind);
    assert_eq!(d1.diagnostic_msg(), LOCAL_HEIGHT_TOO_FAR_BEHIND_MSG);

    // 19_999 behind is NOT too far behind -> UseLocal
    let d2 = evaluate_local_abci_state(fresh_local, &[status_a, status_b]);
    assert_eq!(d2, LocalStateDecision::UseLocal);
    assert_eq!(d2.diagnostic_msg(), INITIALIZING_WITH_LOCAL_STATE_MSG);

    // Stale hardfork by version/round tuple or height < hardfork_height
    let stale_hf_tuple = LocalAbciSnapshot {
        height: 90_000,
        hardfork: Hardfork {
            version: 4,
            round: 999,
        },
        frozen_for_upgrade: false,
    };
    let d3 = evaluate_local_abci_state(stale_hf_tuple, &[status_a, status_b]);
    assert_eq!(d3, LocalStateDecision::StaleHardfork);
    assert_eq!(d3.diagnostic_msg(), LOCAL_HEIGHT_STALE_HARDFORK_MSG);

    // Frozen hardfork upgrade window: local_round + 400 > remote_round (1000+400 > 1399 => Apply)
    let frozen_ok = LocalAbciSnapshot {
        height: 90_000,
        hardfork: hf,
        frozen_for_upgrade: true,
    };
    let d4 = evaluate_local_abci_state(frozen_ok, &[status_a, status_b]);
    assert_eq!(d4, LocalStateDecision::ApplyHardforkUpgrade);
    assert_eq!(d4.diagnostic_msg(), APPLYING_HARDFORK_MSG);

    // At remote_round = 1400 (1000 + 400 <= 1400) => skips upgrade, falls through to UseLocal
    let status_past_window = GossipStatus {
        latest_consensus_round: Some(1400),
        ..status_a
    };
    let d5 = evaluate_local_abci_state(frozen_ok, &[status_past_window, status_b]);
    assert_eq!(d5, LocalStateDecision::UseLocal);
}
