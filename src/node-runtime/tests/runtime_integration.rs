use net_utils::{GossipRpcRequest, GossipStatus, Hardfork, PeerEntry, TcpListener};
use node_runtime::{
    AcceptAllConsensus, BlockSink, Chain, Command, DEFAULT_RESTART_CAP_SECS, FirewallIps,
    GossipConfigInner, GossipConfigReloader, MemoryBlockStore, NodeError, NodePort, PeerTable,
    ReplicaStyle, RestartSupervisor, UNREACHABLE_PEERS_MSG, WaitPlan, check_peer_reachability,
    discover_peers_from, metadata_gate_opens, parse_args, query_gossip_status, replica_style_str,
    serve_one_gossip_rpc, sync_client_blocks,
};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::thread;
use std::time::Duration;

#[test]
fn node_port_exact_mapping_and_compression_exemption() {
    let expected = [
        (NodePort::Gossip, 4001u16, false),
        (NodePort::GossipRpc, 4002, false),
        (NodePort::Consensus, 4003, false),
        (NodePort::NvStream, 4004, false),
        (NodePort::ConsensusAux, 4005, false),
        (NodePort::EvmKvs, 3998, true),
        (NodePort::AbciStream, 3999, true),
    ];
    for (variant, port, local_uncompressed) in expected {
        assert_eq!(variant.port(), port);
        assert_eq!(NodePort::from_port(port), Some(variant));
        assert_eq!(variant.is_local_uncompressed(), local_uncompressed);
        assert_eq!(
            net_utils::should_compress_for_port(4096, port).is_none(),
            local_uncompressed
        );
    }
    assert_eq!(NodePort::from_port(4000), None);
}

#[test]
fn cli_parsing_and_node115_validators() {
    // 1. run-non-validator with output flags
    let parsed = parse_args(&[
        "--chain",
        "Mainnet",
        "run-non-validator",
        "--write-trades",
        "--write-fills",
        "--serve-evm-rpc",
        "--serve-info",
        "--replica-cmds-style",
        "actions-and-responses",
    ])
    .unwrap();
    assert_eq!(parsed.chain, Chain::Mainnet);
    match parsed.command {
        Command::RunNonValidator { output } => {
            assert!(output.serve_evm_rpc);
            assert!(output.serve_info);
            assert_eq!(output.replica_style, ReplicaStyle::ActionsAndResponses);
            assert_eq!(replica_style_str(&output.replica_style), "actions-and-responses");
        }
        other => panic!("unexpected command: {other:?}"),
    }

    // 2. change-validator-profile validates node-ip, bool, and u64 via node115-cli-validators
    let prof = parse_args(&[
        "--chain=Testnet",
        "change-validator-profile",
        "--node-ip",
        "10.20.30.40",
        "--disable-delegations",
        "false",
        "--commission-bps",
        "+500",
    ])
    .unwrap();
    assert_eq!(
        prof.command,
        Command::ChangeValidatorProfile {
            node_ip: Some(Ipv4Addr::new(10, 20, 30, 40)),
            description: None,
            disable_delegations: Some(false),
            commission_bps: Some(500),
            signer: None,
        }
    );

    // 3. Corruption controls: invalid IP, uppercase bool, missing chain
    let bad_ip = parse_args(&[
        "--chain",
        "Mainnet",
        "change-validator-profile",
        "--node-ip",
        "999.1.1.1",
    ])
    .unwrap_err();
    assert!(bad_ip.to_string().contains("NodeIpParseError"));

    let bad_bool = parse_args(&[
        "--chain",
        "Mainnet",
        "change-validator-profile",
        "--disable-delegations",
        "True",
    ])
    .unwrap_err();
    assert!(matches!(bad_bool, NodeError::Cli(_)));

    let missing_chain = parse_args(&["serve-eth-rpc"]).unwrap_err();
    assert!(missing_chain.to_string().contains("The chain is required"));
}

#[test]
fn gossip_config_reload_firewall_and_restart_backoff() {
    // Empty root_node_ips rejected per node/src/gossip_config.rs assertion
    assert!(GossipConfigInner::default_for_chain(Chain::Mainnet, vec![]).is_err());

    let cfg1 = GossipConfigInner::default_for_chain(
        Chain::Mainnet,
        vec![Ipv4Addr::new(10, 0, 0, 1)],
    )
    .unwrap();
    let mut reloader = GossipConfigReloader::new(cfg1.clone(), [100, 0, 0]).unwrap();

    // Same or older stamp does not reload
    assert!(!metadata_gate_opens([100, 0, 0], [100, 0, 0]));
    assert!(!reloader.try_reload([99, 999, 999], cfg1.clone()).unwrap());

    // Newer stamp reloads
    let mut cfg2 = cfg1;
    cfg2.n_gossip_peers = 16;
    assert!(reloader.try_reload([101, 0, 0], cfg2.clone()).unwrap());
    assert_eq!(reloader.current().n_gossip_peers, 16);

    // Signed first dword boundary (negative i32 < 0)
    assert!(metadata_gate_opens([0, 0, 0], [u32::MAX, 0, 0]));

    // Firewall diff & reachability
    let mut fw = FirewallIps::new([Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
    let abci: BTreeSet<_> = [Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)]
        .into_iter()
        .collect();
    let diff = fw.sync_to_abci(&abci);
    assert_eq!(
        diff.abci_minus_firewall,
        [Ipv4Addr::new(10, 0, 0, 3)].into_iter().collect()
    );
    assert_eq!(
        diff.firewall_minus_abci,
        [Ipv4Addr::new(10, 0, 0, 1)].into_iter().collect()
    );
    let err = check_peer_reachability(&[Ipv4Addr::new(10, 0, 0, 3)]).unwrap_err();
    assert!(err.starts_with(UNREACHABLE_PEERS_MSG));

    // Restart backoff: min(2^attempt, 30.0) - 1.0 => 0s (Immediate), 1s, 3s, 7s, 15s, 29s, 29s
    let mut sup = RestartSupervisor::new(DEFAULT_RESTART_CAP_SECS);
    assert_eq!(sup.next_wait(), WaitPlan::Immediate);
    assert_eq!(sup.next_wait(), WaitPlan::Timer(Duration::from_secs(1)));
    assert_eq!(sup.next_wait(), WaitPlan::Timer(Duration::from_secs(3)));
    assert_eq!(sup.next_wait(), WaitPlan::Timer(Duration::from_secs(7)));
    assert_eq!(sup.next_wait(), WaitPlan::Timer(Duration::from_secs(15)));
    assert_eq!(sup.next_wait(), WaitPlan::Timer(Duration::from_secs(29)));
    assert_eq!(sup.next_wait(), WaitPlan::Timer(Duration::from_secs(29)));
}

#[test]
fn loopback_peer_discovery_and_block_sync_over_net_utils() {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = match listener.local_addr().unwrap() {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => unreachable!(),
    };

    let mut seed_store = MemoryBlockStore::new();
    // Include both small (< 1025B raw) and large (> 1025B LZ4 compressed) client blocks!
    seed_store.insert_existing(100, b"block-100-small".to_vec());
    seed_store.insert_existing(101, vec![0xab; 2048]);
    seed_store.insert_existing(102, b"block-102-tail".to_vec());

    let advertised = vec![
        PeerEntry {
            ip: Ipv4Addr::new(10, 1, 2, 3),
            is_validator: true,
            value: 100,
        },
        PeerEntry {
            ip: Ipv4Addr::new(10, 1, 2, 4),
            is_validator: false,
            value: 200,
        },
    ];
    let advertised_status = Some(GossipStatus {
        hardfork_height: 90,
        latest_height: 102,
        hardfork: Hardfork {
            version: 1,
            round: 50,
        },
        latest_consensus_round: Some(55),
    });

    let server = thread::spawn(move || {
        let req1 = serve_one_gossip_rpc(&listener, &advertised, &seed_store, advertised_status).unwrap();
        assert_eq!(req1, GossipRpcRequest::Peers);
        let req2 = serve_one_gossip_rpc(&listener, &advertised, &seed_store, advertised_status).unwrap();
        assert_eq!(
            req2,
            GossipRpcRequest::ClientBlocks {
                start_height: 100,
                end_height: 102
            }
        );
        let req3 = serve_one_gossip_rpc(&listener, &advertised, &seed_store, advertised_status).unwrap();
        assert_eq!(req3, GossipRpcRequest::Status);
    });

    let cfg = GossipConfigInner::default_for_chain(Chain::Local, vec![Ipv4Addr::LOCALHOST]).unwrap();
    let mut table = PeerTable::from_config(&cfg);
    let added = discover_peers_from(addr, &mut table).unwrap();
    assert_eq!(added, 2);
    assert_eq!(table.len(), 3);

    let mut local_store = MemoryBlockStore::new();
    let synced = sync_client_blocks(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr.port()),
        100,
        102,
        &AcceptAllConsensus,
        &mut local_store,
    )
    .unwrap();
    assert_eq!(synced, 3);
    assert_eq!(local_store.latest_height(), 102);
    assert_eq!(local_store.get_range(101, 101)[0].0, vec![0xab; 2048]);

    let status = query_gossip_status(addr).unwrap();
    assert_eq!(status, advertised_status);

    server.join().unwrap();
}
