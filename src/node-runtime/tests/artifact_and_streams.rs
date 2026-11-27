use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::thread;

use bincode_fork::ByteVec;
use net_utils::{AbciStreamGreeting, GreetingHash, TcpListener, WireSignature};
use node_runtime::{
    ARTIFACT_POLL_INTERVAL_SECS, AbciLatencySampler, ArtifactUpdater, INDEX_DID_NOT_INCREASE_MSG,
    IndexedArtifact, IndexedArtifactContent, NODE_ARTIFACT_DIR, NODE_METADATA_FILENAME, NodeError,
    SharedStreamMsg, VISOR_METADATA_FILENAME, exchange_abci_stream_greeting, recv_evm_kvs_stream,
    serve_abci_stream_greeting, serve_evm_kvs_stream,
};

#[test]
fn artifact_updater_enforces_strictly_increasing_index() {
    assert_eq!(NODE_ARTIFACT_DIR, "node-artifact-2");
    assert_eq!(NODE_METADATA_FILENAME, "node_metadata.json");
    assert_eq!(VISOR_METADATA_FILENAME, "visor_metadata.json");
    assert!((ARTIFACT_POLL_INTERVAL_SECS - 5.0).abs() < f64::EPSILON);

    let initial = IndexedArtifact {
        index: 10,
        content: IndexedArtifactContent::NodeMetadata("{\"version\":10}".to_owned()),
    };
    assert_eq!(initial.json_path(NODE_ARTIFACT_DIR), "node-artifact-2/10.json");

    let mut updater = ArtifactUpdater::new(initial);
    assert_eq!(updater.current_index(), 10);

    // Equal or lower index must fail with the binary-observed diagnostic string.
    let same = IndexedArtifact {
        index: 10,
        content: IndexedArtifactContent::VisorMetadata("same".to_owned()),
    };
    let err = updater.apply_update(same).unwrap_err();
    assert!(err.to_string().contains(INDEX_DID_NOT_INCREASE_MSG));
    assert_eq!(updater.current_index(), 10);

    let older = IndexedArtifact {
        index: 9,
        content: IndexedArtifactContent::HotfixMetadata("older".to_owned()),
    };
    assert!(updater.apply_update(older).is_err());

    // Strictly higher index advances the current artifact.
    let newer = IndexedArtifact {
        index: 11,
        content: IndexedArtifactContent::NodeArtifact(vec![0xde, 0xad, 0xbe, 0xef]),
    };
    updater.apply_update(newer.clone()).unwrap();
    assert_eq!(updater.current(), &newer);
}

#[test]
fn shared_stream_msg_and_abci_latency_sampler() {
    let payload = vec![1u64, 2, 3, 4];
    let msg = SharedStreamMsg::encode_bincode(&payload).unwrap();
    assert_eq!(msg.strong_count(), 1);
    let cloned = msg.clone();
    assert_eq!(msg.strong_count(), 2);
    assert_eq!(msg.as_bytes(), cloned.as_bytes());
    drop(cloned);
    assert_eq!(msg.strong_count(), 1);

    let mut sampler = AbciLatencySampler::new(3);
    assert!(sampler.is_empty());
    assert_eq!(sampler.mean_ms(), None);
    sampler.record_ms(10.0);
    sampler.record_ms(20.0);
    sampler.record_ms(30.0);
    assert_eq!(sampler.len(), 3);
    assert!((sampler.mean_ms().unwrap() - 20.0).abs() < 1e-9);
    // Overwrites oldest entry (10.0 -> 40.0) => mean(40, 20, 30) = 30.0
    sampler.record_ms(40.0);
    assert_eq!(sampler.len(), 3);
    assert!((sampler.mean_ms().unwrap() - 30.0).abs() < 1e-9);
}

fn sample_greeting(height: u64, byte: u8) -> AbciStreamGreeting {
    AbciStreamGreeting::Kind0 {
        blob: ByteVec(vec![byte; 8]),
        height,
        hash: Box::new(GreetingHash::Signatures {
            first: [byte; 32],
            left: vec![WireSignature::from_bytes([byte; 65])],
            right: vec![],
            last: [byte.wrapping_add(1); 32],
        }),
    }
}

#[test]
fn abci_stream_greeting_accept_and_reject_over_loopback() {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind loopback");
    let addr = match listener.local_addr().unwrap() {
        SocketAddr::V4(v4) => v4,
        other => panic!("expected v4 addr, got {other}"),
    };

    let expected_client = sample_greeting(115, 0xaa);
    let server_reply = sample_greeting(116, 0xbb);

    let server_reply_clone = server_reply.clone();
    let handle = thread::spawn(move || {
        serve_abci_stream_greeting(&listener, &server_reply_clone, |g| {
            matches!(g, AbciStreamGreeting::Kind0 { height: 115, .. })
        })
    });

    let got_server = exchange_abci_stream_greeting(addr, &expected_client).unwrap();
    let got_client = handle.join().unwrap().unwrap();
    assert_eq!(got_server, server_reply);
    assert_eq!(got_client, expected_client);

    // Rejection path: mismatched client greeting returns PeerInconsistentGreeting
    let listener2 = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind loopback 2");
    let addr2 = match listener2.local_addr().unwrap() {
        SocketAddr::V4(v4) => v4,
        other => panic!("expected v4 addr, got {other}"),
    };
    let wrong_client = sample_greeting(999, 0x11);
    let handle2 = thread::spawn(move || {
        serve_abci_stream_greeting(&listener2, &server_reply, |g| {
            matches!(g, AbciStreamGreeting::Kind0 { height: 115, .. })
        })
    });
    let _client_err = exchange_abci_stream_greeting(addr2, &wrong_client);
    let server_err = handle2.join().unwrap().unwrap_err();
    assert!(matches!(server_err, NodeError::PeerInconsistentGreeting));
}

#[test]
fn evm_kvs_stream_batches_over_loopback() {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind loopback");
    let addr = match listener.local_addr().unwrap() {
        SocketAddr::V4(v4) => v4,
        other => panic!("expected v4 addr, got {other}"),
    };

    let batches = vec![
        vec![
            (ByteVec(b"k1".to_vec()), ByteVec(b"v1".to_vec())),
            (ByteVec(b"k2".to_vec()), ByteVec(b"v2".to_vec())),
        ],
        vec![(ByteVec(b"k3".to_vec()), ByteVec(vec![0x42; 16]))],
    ];
    let batches_clone = batches.clone();
    let handle = thread::spawn(move || serve_evm_kvs_stream(&listener, &batches_clone));

    let received = recv_evm_kvs_stream(addr).unwrap();
    let sent_count = handle.join().unwrap().unwrap();
    assert_eq!(sent_count, 3);
    assert_eq!(
        received,
        vec![
            (b"k1".to_vec(), b"v1".to_vec()),
            (b"k2".to_vec(), b"v2".to_vec()),
            (b"k3".to_vec(), vec![0x42; 16]),
        ]
    );
}
