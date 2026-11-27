use evm_rpc::{
    build_block_height_key, build_storage_key, build_send_raw_tx_json_rpc,
    compute_fee_history_range, decode_block_height_suffix, decode_raw_tx_hex, encode_raw_tx_hex,
    forward_url_for_selector, parse_number_text, select_weighted_rewards,
    validate_log_filter_limits, validate_reward_percentiles, ExpensiveCallLimiter,
    FeeHistoryError, FeeHistoryRange, ForwardErrorKind, HexDecodeError, LimiterSelector,
    MethodRouter, PermitOutcome, RewardRow, RouterError, EVM_RPC_CORE_METHODS,
    EVM_RPC_EXTRA_METHODS, EVM_RPC_WRITE_FORWARD_METHOD, JSONRPC_METHOD_NOT_FOUND,
    MAINNET_EVM_RPC_URL, MAX_FILTER_ITEMS, MAX_PERMIT_COUNT, TESTNET_EVM_RPC_URL,
};

#[test]
fn all_29_methods_register_and_reject_duplicates() {
    let mut core = MethodRouter::new();
    for (idx, &m) in EVM_RPC_CORE_METHODS.iter().enumerate() {
        core.register(m, idx).unwrap();
    }
    let mut extra = MethodRouter::new();
    for (i, &m) in EVM_RPC_EXTRA_METHODS.iter().enumerate() {
        extra.register(m, 100 + i).unwrap();
    }
    extra.register(EVM_RPC_WRITE_FORWARD_METHOD, 200).unwrap();
    core.merge(extra).unwrap();
    assert_eq!(core.len(), 29);
    assert_eq!(core.get("eth_usingBigBlocks"), Ok(&25));
    assert_eq!(core.get("eth_sendRawTransaction"), Ok(&200));

    let missing = core.get("eth_nonexistent").unwrap_err();
    assert_eq!(missing.jsonrpc_code(), JSONRPC_METHOD_NOT_FOUND);
    assert_eq!(missing.message(), "Method not found");

    // Duplicate preflight rejects without mutating router:
    let mut dup = MethodRouter::new();
    dup.register("eth_newMethod", 300).unwrap();
    dup.register("eth_call", 301).unwrap();
    assert_eq!(
        core.merge(dup),
        Err(RouterError::DuplicateMethod("eth_call".to_string()))
    );
    assert_eq!(core.len(), 29);
}

#[test]
fn raw_tx_forwarder_selector_and_strict_hex_rules() {
    assert_eq!(
        forward_url_for_selector(0).unwrap_err().kind,
        ForwardErrorKind::UnsupportedChain
    );
    assert_eq!(
        forward_url_for_selector(1).unwrap_err().kind,
        ForwardErrorKind::UnsupportedChain
    );
    assert_eq!(forward_url_for_selector(2), Ok(TESTNET_EVM_RPC_URL));
    assert_eq!(forward_url_for_selector(3), Ok(MAINNET_EVM_RPC_URL));
    assert_eq!(forward_url_for_selector(255), Ok(MAINNET_EVM_RPC_URL));

    // Exact RE-011-evm-raw-forward-115 hex decoder edge cases:
    assert_eq!(decode_raw_tx_hex(b"0x0"), Err(HexDecodeError::OddLength));
    assert_eq!(
        decode_raw_tx_hex(b"0X"),
        Err(HexDecodeError::InvalidCharacter { byte: b'X', index: 1 })
    );
    assert_eq!(
        decode_raw_tx_hex(b"0xzz"),
        Err(HexDecodeError::InvalidCharacter { byte: b'z', index: 0 })
    );
    let raw = decode_raw_tx_hex(b"0xDeAdBeEf").unwrap();
    assert_eq!(raw, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(encode_raw_tx_hex(&raw), "0xdeadbeef");
    assert_eq!(
        build_send_raw_tx_json_rpc(&raw),
        r#"{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xdeadbeef"],"id":1}"#
    );
}

#[test]
fn permit_limiter_and_filter_bounds() {
    let mut lim = ExpensiveCallLimiter::new(2, usize::MAX, 5.0, 10.0);
    assert_eq!(lim.limit(LimiterSelector::FilterLogs), MAX_PERMIT_COUNT);
    assert_eq!(
        lim.try_acquire(LimiterSelector::CallOrEstimateGas),
        PermitOutcome::Acquired
    );
    assert_eq!(
        lim.try_acquire(LimiterSelector::CallOrEstimateGas),
        PermitOutcome::Acquired
    );
    assert_eq!(
        lim.try_acquire(LimiterSelector::CallOrEstimateGas),
        PermitOutcome::Pending
    );
    lim.release(LimiterSelector::CallOrEstimateGas);
    assert_eq!(
        lim.try_acquire(LimiterSelector::CallOrEstimateGas),
        PermitOutcome::Acquired
    );
    lim.close(LimiterSelector::FilterLogs);
    assert_eq!(
        lim.try_acquire(LimiterSelector::FilterLogs),
        PermitOutcome::RejectedOrTimedOut
    );

    assert!(validate_log_filter_limits(MAX_FILTER_ITEMS, [1000, 0, 500, 1000]));
    assert!(!validate_log_filter_limits(MAX_FILTER_ITEMS + 1, [0; 4]));
    assert!(!validate_log_filter_limits(0, [0, 0, 1001, 0]));
}

#[test]
fn fee_history_and_store_key_codecs() {
    assert!(validate_reward_percentiles(&[10.0, 50.0, 90.0]).is_ok());
    assert_eq!(
        validate_reward_percentiles(&[50.0, 10.0]),
        Err(FeeHistoryError::InvalidRewardPercentiles)
    );
    assert_eq!(
        validate_reward_percentiles(&vec![1.0; 101]),
        Err(FeeHistoryError::InvalidRewardPercentiles)
    );

    let latest = parse_number_text("latest").unwrap();
    assert_eq!(
        compute_fee_history_range(20, latest, 100),
        Ok(Some(FeeHistoryRange {
            oldest_block: 96,
            newest_block: 100,
            count: 5,
        }))
    );
    let pending = parse_number_text("pending").unwrap();
    assert_eq!(
        compute_fee_history_range(5, pending, 100),
        Ok(Some(FeeHistoryRange {
            oldest_block: 97,
            newest_block: 100,
            count: 4,
        }))
    );
    let max_num = parse_number_text("0xffffffffffffffff").unwrap();
    assert_eq!(
        compute_fee_history_range(1, max_num, 100),
        Err(FeeHistoryError::InvalidBlockRange)
    );

    let rows = [
        RewardRow { effective_priority_fee: 10, gas_used: 30 },
        RewardRow { effective_priority_fee: 20, gas_used: 70 },
    ];
    assert_eq!(
        select_weighted_rewards(&rows, 100, &[0.0, 30.0, 31.0, 100.0]),
        Ok(vec![10, 10, 20, 20])
    );

    let hk = build_block_height_key(b"Eb", 0x0102_0304_0506_0708);
    assert_eq!(decode_block_height_suffix(b"Eb", &hk), Some(0x0102_0304_0506_0708));
    let sk = build_storage_key(b"Es", &[0x11; 20], [1, 2, 3, 4]);
    assert_eq!(sk.len(), 54);
}
