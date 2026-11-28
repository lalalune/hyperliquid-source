use evm_rpc::{
    compute_fee_history_range, parse_number_text, select_weighted_rewards, FeeHistoryResult,
    RewardRow,
};

#[test]
fn empty_required_fields_and_explicitly_requested_empty_rewards() {
    let mut result = FeeHistoryResult::default();
    assert_eq!(
        result.to_string(),
        r#"{"gasUsedRatio":[],"oldestBlock":"0x0"}"#
    );
    result.reward = Some(vec![]);
    assert_eq!(
        result.to_string(),
        r#"{"gasUsedRatio":[],"oldestBlock":"0x0","reward":[]}"#
    );
    result.reward = Some(vec![vec![]]);
    assert_eq!(
        result.to_string(),
        r#"{"gasUsedRatio":[],"oldestBlock":"0x0","reward":[[]]}"#
    );
}

#[test]
fn encodes_the_existing_range_and_reward_selection_results() {
    let range = compute_fee_history_range(1, parse_number_text("0x2a").unwrap(), 100)
        .unwrap()
        .unwrap();
    let rows = [
        RewardRow {
            effective_priority_fee: 0,
            gas_used: 1,
        },
        RewardRow {
            effective_priority_fee: u128::MAX,
            gas_used: 1,
        },
    ];
    let result = FeeHistoryResult {
        base_fee_per_gas: vec![0, 16],
        gas_used_ratio: vec![0.25],
        base_fee_per_blob_gas: vec![4096, 1],
        blob_gas_used_ratio: vec![0.5],
        oldest_block: range.oldest_block,
        reward: Some(vec![
            select_weighted_rewards(&rows, 2, &[0.0, 100.0]).unwrap()
        ]),
    };
    assert_eq!(
        result.to_string(),
        concat!(
            r#"{"baseFeePerGas":["0x0","0x10"],"gasUsedRatio":[0.25],"#,
            r#""baseFeePerBlobGas":["0x1000","0x1"],"blobGasUsedRatio":[0.5],"#,
            r#""oldestBlock":"0x2a","reward":[["0x0","0xffffffffffffffffffffffffffffffff"]]}"#,
        )
    );
}

#[test]
fn optional_blob_fields_are_independent() {
    let mut result = FeeHistoryResult {
        oldest_block: u64::MAX,
        ..Default::default()
    };
    result.blob_gas_used_ratio.push(1.0);
    assert_eq!(
        result.to_string(),
        r#"{"gasUsedRatio":[],"blobGasUsedRatio":[1.0],"oldestBlock":"0xffffffffffffffff"}"#
    );
    result.blob_gas_used_ratio.clear();
    result.base_fee_per_blob_gas.push(0);
    assert_eq!(
        result.to_string(),
        r#"{"gasUsedRatio":[],"baseFeePerBlobGas":["0x0"],"oldestBlock":"0xffffffffffffffff"}"#
    );
}

#[test]
fn nonfinite_ratio_values_emit_json_null() {
    let result = FeeHistoryResult {
        gas_used_ratio: vec![f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0],
        ..Default::default()
    };
    assert_eq!(
        result.to_string(),
        r#"{"gasUsedRatio":[null,null,null,-0.0],"oldestBlock":"0x0"}"#
    );
}
