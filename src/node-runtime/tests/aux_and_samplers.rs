use node_runtime::{
    AUX_BATCH_VS_STREAM_CONFLICT_MSG, AUX_OUTPUT_STREAMS, AuxStreamConfig, GroupAndSeqSampler,
    NESTED_RUNTIME_ERROR_MSG, PriorityChannel, block_on_sync,
};

#[test]
fn aux_stream_config_enforces_node115_names_and_mutual_exclusion() {
    assert_eq!(AUX_OUTPUT_STREAMS.len(), 10);
    assert_eq!(AUX_OUTPUT_STREAMS[0], "node_trades");
    assert_eq!(AUX_OUTPUT_STREAMS[9], "dex_user_clearinghouse_states");

    let valid = AuxStreamConfig {
        batch_by_block: true,
        stream_with_block_info: false,
        enabled_streams: vec!["node_trades", "node_fills", "evm_block_and_receipts"],
    };
    valid.validate().unwrap();

    let conflict = AuxStreamConfig {
        batch_by_block: true,
        stream_with_block_info: true,
        enabled_streams: vec!["node_trades"],
    };
    let err = conflict.validate().unwrap_err();
    assert!(err.to_string().contains(AUX_BATCH_VS_STREAM_CONFLICT_MSG));

    let unknown = AuxStreamConfig {
        batch_by_block: false,
        stream_with_block_info: false,
        enabled_streams: vec!["nonexistent_stream"],
    };
    assert!(unknown.validate().is_err());
}

#[test]
fn priority_channel_group_sampler_and_block_on_guard() {
    let mut ch = PriorityChannel::new(2);
    ch.try_send_normal("n1").unwrap();
    ch.try_send_normal("n2").unwrap();
    assert_eq!(ch.try_send_normal("n3"), Err("n3"));
    ch.try_send_high("h1").unwrap();
    assert_eq!(ch.len(), 3);
    // High priority drains before normal priority
    assert_eq!(ch.try_recv(), Some("h1"));
    assert_eq!(ch.try_recv(), Some("n1"));
    assert_eq!(ch.try_recv(), Some("n2"));
    assert_eq!(ch.try_recv(), None);
    assert!(ch.is_empty());

    let mut sampler = GroupAndSeqSampler::new();
    sampler.record_nanos(7, 250_000_000);
    sampler.record_secs(7, f64::INFINITY); // clamped to 0.0 per 0x5b29977
    let stats = sampler.stats(7).unwrap();
    assert_eq!(stats.count, 2);
    assert!((stats.total_secs - 0.25).abs() < 1e-12);
    assert!((stats.max_secs - 0.25).abs() < 1e-12);

    // Nested block_on_sync rejected with node/src/utils.rs message
    let inner_res = block_on_sync(|| block_on_sync(|| 42u32)).unwrap();
    let err = inner_res.unwrap_err();
    assert!(err.to_string().contains(NESTED_RUNTIME_ERROR_MSG));
    // Guard resets cleanly after exit
    assert_eq!(block_on_sync(|| 99u32).unwrap(), 99);
}

#[test]
fn group_sampler_preserves_split_duration_rounding_in_reported_stats() {
    let mut sampler = GroupAndSeqSampler::new();
    // 1.118 s and 4.137 s exercise opposite directions of the one-ULP difference.
    for (group, nanos, expected_bits) in [
        (7, 1_118_000_000, 0x3ff1_e353_f7ce_d916),
        (8, 4_137_000_000, 0x4010_8c49_ba5e_3540),
    ] {
        sampler.record_nanos(group, nanos);
        let stats = sampler.stats(group).unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.max_secs.to_bits(), expected_bits);
        assert_eq!(stats.total_secs.to_bits(), expected_bits);
    }
    sampler.record_nanos(7, 1_118_000_000);
    let repeated = sampler.stats(7).unwrap();
    assert_eq!(repeated.count, 2);
    assert_eq!(repeated.total_secs.to_bits(), 0x4001_e353_f7ce_d916);
    assert_eq!(repeated.max_secs.to_bits(), 0x3ff1_e353_f7ce_d916);
}
