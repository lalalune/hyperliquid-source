use net_utils::framing::{h2_framing, http_header_writer, newline_requests};
use net_utils::gossip::greeting_encoder::{self, Greeting};
use net_utils::{
    AlertConfig, BoundedChannel, ChannelError, ClientBlocksError, DEFAULT_MAX_FRAME_BYTES,
    Direction, GossipRpcRequest, GossipRpcResponse, GossipStatus, Hardfork, IpSemaphore, Lz4Error,
    Lz4Stats, PEERS_RESPONSE_LIMIT, PeerEntry, ProfiledRwLock, RateLimitDecision, RateLimiter,
    RetryPolicy, SemaphoreError, TcpClient, TcpError, TcpListener, TrafficRecorder,
    compress_prepend_size, decompress_size_prepended, encode_frame, read_bincode_frame, read_frame,
    should_compress_for_port, sleep_retry, write_bincode_frame,
};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn lz4_compress_decompress_roundtrip_small_and_large_tables() {
    // 1. Short input (< 12 bytes, literal-only path)
    let short = b"hyperliquid";
    let comp = compress_prepend_size(short).unwrap();
    assert_eq!(decompress_size_prepended(&comp, 64).unwrap(), short);

    // 2. Repetitive medium payload (SmallTable, 1025..65534)
    let mut medium = Vec::new();
    for i in 0..400u32 {
        medium.extend_from_slice(b"HYPERLIQUID_NODE115_FRAME_PAYLOAD_");
        medium.extend_from_slice(&i.to_le_bytes());
    }
    assert!(medium.len() >= 1025 && medium.len() < 65_535);
    let comp_med = compress_prepend_size(&medium).unwrap();
    assert!(comp_med.len() < medium.len() / 2, "expected real LZ4 compression");
    assert_eq!(
        decompress_size_prepended(&comp_med, medium.len() as u64).unwrap(),
        medium
    );

    // 3. Large payload (>= 65535 bytes -> LargeTable)
    let mut large = Vec::with_capacity(80_000);
    for i in 0..2_500u32 {
        large.extend_from_slice(b"NODE115_LARGE_TABLE_BLOCK___");
        large.extend_from_slice(&(i % 64).to_le_bytes());
    }
    assert!(large.len() >= 65_535);
    let comp_large = compress_prepend_size(&large).unwrap();
    assert!(comp_large.len() < large.len() / 4);
    assert_eq!(
        decompress_size_prepended(&comp_large, large.len() as u64).unwrap(),
        large
    );

    // 4. Corruption / limit boundary: announced size exceeds max_output_bytes
    let err = decompress_size_prepended(&comp_med, (medium.len() - 1) as u64).unwrap_err();
    assert!(matches!(err, Lz4Error::Decode(_)));
    assert!(err.to_string().starts_with("decompress_lz4 failure: "));
}

#[test]
fn tcp_compression_policy_and_5byte_frame_codec() {
    // < 1025 bytes -> raw (flag 0)
    assert!(should_compress_for_port(1024, 4001).is_none());
    let (raw_frame, compressed) = encode_frame(&vec![0x42; 1024], 4001).unwrap();
    assert!(!compressed);
    assert_eq!(raw_frame[4], 0);
    assert_eq!(u32::from_be_bytes(raw_frame[..4].try_into().unwrap()), 1024);

    // >= 1025 bytes on port 4001 -> compressed (flag 1)
    assert!(should_compress_for_port(1025, 4001).is_some());
    let payload = vec![b'A'; 4096];
    let (lz4_frame, compressed) = encode_frame(&payload, 4001).unwrap();
    assert!(compressed);
    assert_eq!(lz4_frame[4], 1);
    let mut cursor = Cursor::new(lz4_frame);
    let (decoded, hdr) = read_frame(&mut cursor, DEFAULT_MAX_FRAME_BYTES, 8192).unwrap();
    assert_eq!(hdr.flag, 1);
    assert_eq!(decoded, payload);

    // Ports 3998 and 3999 NEVER compress even when >= 1025 bytes (node #115 rule)
    for exempt_port in [3998u16, 3999] {
        assert!(should_compress_for_port(4096, exempt_port).is_none());
        let (frame, compressed) = encode_frame(&payload, exempt_port).unwrap();
        assert!(!compressed);
        assert_eq!(frame[4], 0);
    }

    // OverLimit rejection before payload allocation
    let mut over = Cursor::new([0, 0, 1, 0, 0]); // 256 bytes
    let err = read_frame(&mut over, 255, 255).unwrap_err();
    assert!(matches!(
        err,
        TcpError::OverLimit {
            payload_len: 256,
            maximum: 255
        }
    ));
}

#[test]
fn loopback_tcp_client_listener_bincode_gossip_roundtrip() {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut conn, _peer) = listener.accept().unwrap();
        let req: GossipRpcRequest = conn.recv_bincode(Some(1024)).unwrap();
        assert_eq!(req, GossipRpcRequest::Peers);
        let resp = GossipRpcResponse::Peers(vec![
            PeerEntry {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                is_validator: true,
                value: 4001,
            },
            PeerEntry {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                is_validator: false,
                value: 4002,
            },
        ]);
        conn.send_bincode(resp).unwrap();
    });

    let mut client = TcpClient::new(addr, "test_gossip").unwrap();
    assert!(!client.is_connected());
    assert!(matches!(
        client.send_bincode_and_read_response::<_, GossipRpcResponse>(GossipRpcRequest::Peers, None),
        Err(TcpError::NotConnected)
    ));

    client.connect().unwrap();
    assert!(client.is_connected());
    let resp: GossipRpcResponse = client
        .send_bincode_and_read_response(GossipRpcRequest::Peers, Some(PEERS_RESPONSE_LIMIT))
        .unwrap();
    assert_eq!(
        resp,
        GossipRpcResponse::Peers(vec![
            PeerEntry {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                is_validator: true,
                value: 4001,
            },
            PeerEntry {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                is_validator: false,
                value: 4002,
            },
        ])
    );
    server.join().unwrap();
}

#[test]
fn gossip_rpc_response_exact_node115_wire_bytes() {
    use bincode_fork::{decode_from_slice, encode_to_vec, standard};

    // Tag 0 = ClientBlocks(Err(ClientBlocksError)) covering all 7 variants 0..=6
    let errs = [
        (ClientBlocksError::PeerOnlyRequest, vec![0, 1, 0]),
        (
            ClientBlocksError::InvalidRange {
                start_round: 10,
                end_round: 5,
            },
            vec![0, 1, 1, 10, 5],
        ),
        (ClientBlocksError::RangeTooLarge, vec![0, 1, 2]),
        (ClientBlocksError::RateLimited, vec![0, 1, 3]),
        (ClientBlocksError::NoClientBlocks, vec![0, 1, 4]),
        (
            ClientBlocksError::RoundTooSmall {
                start_round: 1,
                first_parent_round: 20,
            },
            vec![0, 1, 5, 1, 20],
        ),
        (
            ClientBlocksError::RoundTooLarge {
                end_round: 99,
                max_round: 50,
            },
            vec![0, 1, 6, 99, 50],
        ),
    ];
    for (err, expected) in errs {
        let resp = GossipRpcResponse::ClientBlocks(Err(err));
        let wire = encode_to_vec(&resp, standard()).unwrap();
        assert_eq!(wire, expected, "wire mismatch for {err:?}");
        let (back, consumed): (GossipRpcResponse, usize) =
            decode_from_slice(&wire, standard()).unwrap();
        assert_eq!(back, resp);
        assert_eq!(consumed, wire.len());
    }
    // Tag 7 out of range must fail with UnexpectedVariant
    assert!(decode_from_slice::<GossipRpcResponse>(&[0, 1, 7], standard()).is_err());

    // Tag 1 = Peers(Vec<PeerEntry>) with NodeIp tag 0 + 4 IPv4 bytes + bool + u64 varint
    let peers = GossipRpcResponse::Peers(vec![PeerEntry {
        ip: Ipv4Addr::new(10, 20, 30, 40),
        is_validator: true,
        value: 7,
    }]);
    let peers_wire = encode_to_vec(&peers, standard()).unwrap();
    assert_eq!(peers_wire, vec![1, 1, 0, 10, 20, 30, 40, 1, 7]);
    let (peers_back, _): (GossipRpcResponse, usize) =
        decode_from_slice(&peers_wire, standard()).unwrap();
    assert_eq!(peers_back, peers);

    // Tag 2 = GossipStatus(Option<GossipStatus>) with 4 u64 + Option<u64>
    let status = GossipRpcResponse::GossipStatus(Some(GossipStatus {
        hardfork_height: 100,
        latest_height: 120,
        hardfork: Hardfork {
            version: 3,
            round: 40,
        },
        latest_consensus_round: Some(45),
    }));
    let status_wire = encode_to_vec(&status, standard()).unwrap();
    assert_eq!(status_wire, vec![2, 1, 100, 120, 3, 40, 1, 45]);
    let (status_back, _): (GossipRpcResponse, usize) =
        decode_from_slice(&status_wire, standard()).unwrap();
    assert_eq!(status_back, status);
}

#[test]
fn bincode_frame_corruption_preserves_node115_error_prefix() {
    let mut wire = Vec::new();
    // Write a valid frame containing an invalid GossipRpcRequest discriminant (99)
    write_bincode_frame(&mut wire, 99u32, 4001).unwrap();
    let mut cursor = Cursor::new(wire);
    let err =
        read_bincode_frame::<_, GossipRpcRequest>(&mut cursor, 4096, 4096, Some(1024)).unwrap_err();
    assert!(err.to_string().starts_with("TcpRead::bincode err: "));
}

#[test]
fn ip_semaphore_rate_limiter_stats_and_primitives() {
    let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));

    // IpSemaphore: global=3, per_ip=2
    let sem = IpSemaphore::new("gossip", 3, 2);
    assert_eq!(sem.metric_name(), "gossip_ip_semaphore");
    let p1 = sem.try_acquire(ip_a).unwrap();
    let p2 = sem.try_acquire(ip_a).unwrap();
    assert_eq!(sem.try_acquire(ip_a).unwrap_err(), SemaphoreError::IpExhausted);
    assert_eq!(sem.global_available(), 1);
    let p3 = sem.try_acquire(ip_b).unwrap();
    assert_eq!(
        sem.try_acquire(ip_b).unwrap_err(),
        SemaphoreError::GlobalExhausted
    );
    drop((p1, p2, p3));
    assert_eq!(sem.global_available(), 3);
    assert_eq!(sem.ip_in_use(ip_a), 0);

    // RateLimiter
    let now = Instant::now();
    let mut rl = RateLimiter::new(
        Duration::from_secs(10),
        1000,
        1500,
        Some(AlertConfig {
            bucket_limit_mult_threshold: 0.8,
        }),
    );
    assert_eq!(rl.check_and_charge(ip_a, 500, now), RateLimitDecision::Allowed);
    assert_eq!(
        rl.check_and_charge(ip_a, 400, now),
        RateLimitDecision::AllowedWithAlert
    );
    assert_eq!(
        rl.check_and_charge(ip_a, 200, now),
        RateLimitDecision::RejectedPerIp
    );
    assert_eq!(
        rl.check_and_charge(ip_b, 700, now),
        RateLimitDecision::RejectedGlobal
    );
    // Window rollover clears maps
    assert_eq!(
        rl.check_and_charge(ip_a, 500, now + Duration::from_secs(11)),
        RateLimitDecision::Allowed
    );

    // Lz4Stats + TrafficRecorder
    let mut lz4 = Lz4Stats::new();
    lz4.record(Direction::Out, 4000, 1000, true);
    assert!((lz4.compression_ratio(Direction::Out) - 0.25).abs() < 1e-9);
    assert_eq!(Lz4Stats::metric_prefix(Direction::In, "gossip"), "tcp_lz4/in_gossip");

    let mut rec = TrafficRecorder::new();
    rec.record(Direction::In, ip_a, 1234);
    assert_eq!(rec.total_in_bytes, 1234);

    // ProfiledRwLock + BoundedChannel + sleep_retry
    let lock = ProfiledRwLock::new("peers", 41u64);
    assert_eq!(lock.metric_name(), "profiled_rw_lock/peers");
    *lock.write() += 1;
    assert_eq!(*lock.read(), 42);
    assert_eq!((lock.read_count(), lock.write_count()), (1, 1));

    let ch = BoundedChannel::new("gossip_rx", 2);
    ch.try_send(10u32).unwrap();
    ch.try_send(20u32).unwrap();
    assert_eq!(ch.try_send(30u32), Err((ChannelError::Full, 30)));
    assert_eq!(ch.try_recv(), Ok(10));
    assert_eq!(ch.stats(), (2, 1, 1));

    let mut calls = 0usize;
    let (val, retries) = sleep_retry(
        RetryPolicy {
            max_retries: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        },
        |_| {
            calls += 1;
            if calls < 3 { Err("transient") } else { Ok(99) }
        },
    )
    .unwrap();
    assert_eq!((val, retries), (99, 2));

    // Greeting encoder + HTTP/2 framing + HTTP header writer + newline requests smoke check
    let g_bytes = greeting_encoder::encode(&Greeting::Kind1 {
        at_18: 7,
        at_8: 8,
        at_10: 9,
    })
    .unwrap();
    assert_eq!(g_bytes, vec![1, 7, 8, 9]);

    let (h2_cfg, _continuations) = h2_framing::h2_limits(16_384).unwrap();
    let h2_pkt = [0u8, 0, 1, 0, 0, 0, 0, 0, 0, 42];
    let step1 = h2_framing::decode(h2_cfg, h2_framing::State::Head, &h2_pkt);
    assert_eq!(step1.status, h2_framing::Status::Frame);
    assert_eq!(step1.frame_length, 10);

    let mut hdr_out = [0u8; 64];
    let hdr_len = http_header_writer::append(
        &[http_header_writer::Group {
            name: http_header_writer::Name::Builtin(29), // content-type
            values: &[b"application/json"],
        }],
        &[],
        false,
        &mut hdr_out,
        0,
    )
    .unwrap();
    assert_eq!(&hdr_out[..hdr_len], b"content-type: application/json\r\n");

    let mut lines = Vec::new();
    let mut flag = 0u8;
    newline_requests::write_lines(b"a\nb\n", &mut flag, |_, chunk| {
        lines.push(chunk.to_vec());
        0
    });
    assert_eq!(lines, vec![b"a\n".to_vec(), b"    ".to_vec(), b"b\n".to_vec()]);
}
