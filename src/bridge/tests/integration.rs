use std::collections::BTreeMap;

use bridge::{
    apply_bridge_request_mutation, arb_chain_id_for, bridge2_contract_lookup_key,
    encode_request_withdrawal, flatten_bridge_words, keccak256, BridgeRequest, BridgeRole,
    EthEventId, Node115BridgeEvent, VoteEthDepositAction, WithdrawalMutationRequest,
    WithdrawalMutationState, WithdrawalMutationStop, ARB_MAINNET_CHAIN_ID, ARB_SEPOLIA_CHAIN_ID,
    BRIDGE2_SERIALIZED_FIELD_COUNT, BRIDGE_AGENT_SOURCE,
};
use global_constants::ChainName;

#[test]
fn request_withdrawal_tag5_matches_micro_crate_and_synthetic_keccak_vector() {
    let user = [0x11; 20];
    let dest = [0x22; 20];
    let req = BridgeRequest::RequestWithdrawal {
        user,
        destination: dest,
        usd: 0x0102_0304_0506_0708,
        nonce: 0x1112_1314_1516_1718,
    };
    assert_eq!(req.tag(), 5);
    assert_eq!(
        req.abi_encode(),
        encode_request_withdrawal(&user, &dest, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718)
            .to_vec()
    );

    // Cross-check word-flatten + preimage digest consistency:
    let contract = [0xaa; 20];
    let inner = req.inner_hash();
    let mut flat_in = [0u8; 52];
    flat_in[..20].copy_from_slice(&contract);
    flat_in[20..].copy_from_slice(&inner);
    let flat_preimage = flatten_bridge_words(&flat_in);
    let expected_conn_id = keccak256(flat_preimage.as_digest_input());

    let mainnet = req.to_agent_payload(ChainName::Mainnet, &contract);
    assert_eq!(mainnet.source, BRIDGE_AGENT_SOURCE);
    assert_eq!(mainnet.connection_id, expected_conn_id);
    assert_eq!(mainnet.arb_chain_id, ARB_MAINNET_CHAIN_ID);
    assert_eq!(arb_chain_id_for(ChainName::Testnet), ARB_SEPOLIA_CHAIN_ID);
    assert_eq!(arb_chain_id_for(ChainName::Sandbox), ARB_SEPOLIA_CHAIN_ID);
    assert_eq!(arb_chain_id_for(ChainName::Local), ARB_SEPOLIA_CHAIN_ID);
    assert_eq!(bridge2_contract_lookup_key(ChainName::Mainnet), "Bridge2Mainnet");
    assert_eq!(bridge2_contract_lookup_key(ChainName::Testnet), "Bridge2Testnet");
}

#[test]
fn all_8_bridge_request_tags_encode_exact_abi_layouts() {
    // Tag 0: ModifyRole (Locker & Finalizer) -> 4 head words + 2 string tail words = 192 bytes.
    let mod_locker = BridgeRequest::ModifyRole {
        role: BridgeRole::Locker,
        user: [0x33; 20],
        active: true,
        nonce: 7,
    };
    let enc0 = mod_locker.abi_encode();
    assert_eq!(mod_locker.tag(), 0);
    assert_eq!(enc0.len(), 192);
    assert_eq!(&enc0[28..32], &128u32.to_be_bytes());
    assert_eq!(&enc0[44..64], &[0x33; 20]);
    assert_eq!(enc0[95], 1);
    assert_eq!(&enc0[120..128], &7u64.to_be_bytes());
    assert_eq!(&enc0[156..160], &12u32.to_be_bytes());
    assert_eq!(&enc0[160..172], b"modifyLocker");

    let mod_fin = BridgeRequest::ModifyRole {
        role: BridgeRole::Finalizer,
        user: [0x44; 20],
        active: false,
        nonce: 8,
    };
    let enc0b = mod_fin.abi_encode();
    assert_eq!(&enc0b[156..160], &15u32.to_be_bytes());
    assert_eq!(&enc0b[160..175], b"modifyFinalizer");

    // Tags 1, 2, 3: (string, uint64, uint64) -> 3 head + 2 tail = 160 bytes.
    for (req, expected_tag, expected_label) in [
        (
            BridgeRequest::ChangeDisputePeriodSeconds {
                dispute_period_seconds: 3600,
                nonce: 1,
            },
            1u8,
            b"changeDisputePeriodSeconds".as_slice(),
        ),
        (
            BridgeRequest::ChangeBlockDurationMillis {
                block_duration_millis: 200,
                nonce: 2,
            },
            2u8,
            b"changeBlockDurationMillis".as_slice(),
        ),
        (
            BridgeRequest::ChangeLockerThreshold {
                locker_threshold: 3,
                nonce: 3,
            },
            3u8,
            b"changeLockerThreshold".as_slice(),
        ),
    ] {
        assert_eq!(req.tag(), expected_tag);
        let enc = req.abi_encode();
        assert_eq!(enc.len(), 160);
        assert_eq!(&enc[28..32], &96u32.to_be_bytes());
        assert_eq!(&enc[124..128], &(expected_label.len() as u32).to_be_bytes());
        assert_eq!(&enc[128..128 + expected_label.len()], expected_label);
    }

    // Tag 4: UpdateValidatorSet -> (string "updateValidatorSet", uint64 epoch, address[], address[], uint64[])
    let upd = BridgeRequest::UpdateValidatorSet {
        epoch: 42,
        hot_addresses: vec![[0x01; 20], [0x02; 20]],
        cold_addresses: vec![[0x03; 20], [0x04; 20]],
        powers: vec![100, 200],
    };
    let enc4 = upd.abi_encode();
    assert_eq!(upd.tag(), 4);
    // Head = 5 words (160B): [offset_str=160, epoch=42, offset_hot=224, offset_cold=320, offset_powers=416]
    assert_eq!(&enc4[28..32], &160u32.to_be_bytes());
    assert_eq!(&enc4[56..64], &42u64.to_be_bytes());
    assert_eq!(&enc4[92..96], &224u32.to_be_bytes());
    assert_eq!(&enc4[124..128], &320u32.to_be_bytes());
    assert_eq!(&enc4[156..160], &416u32.to_be_bytes());
    assert_eq!(&enc4[192..210], b"updateValidatorSet");

    // Tag 6: Unlock -> (string "unlock", uint64 epoch, address[], address[], uint64[], uint64 nonce)
    let unlock = BridgeRequest::Unlock {
        epoch: 9,
        hot_addresses: vec![[0x0a; 20]],
        cold_addresses: vec![[0x0b; 20]],
        powers: vec![500],
        nonce: 99,
    };
    let enc6 = unlock.abi_encode();
    assert_eq!(unlock.tag(), 6);
    assert_eq!(&enc6[28..32], &192u32.to_be_bytes());
    assert_eq!(&enc6[56..64], &9u64.to_be_bytes());
    assert_eq!(&enc6[184..192], &99u64.to_be_bytes());
    assert_eq!(&enc6[224..230], b"unlock");

    // Tag 7: InvalidateWithdrawals -> (string "invalidateWithdrawals", bytes32[], uint64 nonce)
    let inv = BridgeRequest::InvalidateWithdrawals {
        messages: vec![[0x55; 32], [0x66; 32]],
        nonce: 77,
    };
    let enc7 = inv.abi_encode();
    assert_eq!(inv.tag(), 7);
    assert_eq!(&enc7[28..32], &96u32.to_be_bytes());
    assert_eq!(&enc7[60..64], &160u32.to_be_bytes());
    assert_eq!(&enc7[88..96], &77u64.to_be_bytes());
    assert_eq!(&enc7[128..149], b"invalidateWithdrawals");
    assert_eq!(&enc7[188..192], &2u32.to_be_bytes());
    assert_eq!(&enc7[192..224], &[0x55; 32]);
    assert_eq!(&enc7[224..256], &[0x66; 32]);
}

#[test]
fn eth_event_wire_and_mutation_state_join_cleanly() {
    let event = EthEventId {
        block_number: 12345,
        t: 1,
        event_type: Node115BridgeEvent::Deposit,
        log_index: 2,
        tx_hash: [0xab; 32],
    };
    let action = VoteEthDepositAction {
        user: [0xcd; 20],
        usd: 1_000_000,
        eth_id: event,
    };
    let flat_named = action.encode_flat_msgpack(true);
    let flat_compact = action.encode_flat_msgpack(false);
    let nested_named = action.encode_nested_msgpack(true);
    let nested_compact = action.encode_nested_msgpack(false);
    assert_eq!(flat_named[0], 0x84);
    assert_eq!(flat_compact[0], 0x94);
    assert_eq!(nested_named[0], 0x82);
    assert_eq!(nested_compact[0], 0x92);
    let json = action.to_flat_json_string();
    assert!(json.contains(r#""type":"VoteEthDepositAction""#));
    assert!(json.contains(r#""e":"Deposit""#));

    let mut st = WithdrawalMutationState {
        requests: BTreeMap::new(),
        aggregate: 500,
    };
    let key = bridge::BridgeRequestKey {
        address: [1; 20],
        word: 10,
    };
    assert_eq!(
        apply_bridge_request_mutation(
            &mut st,
            key.clone(),
            WithdrawalMutationRequest {
                amount: 200,
                recipient: [2; 20]
            }
        ),
        WithdrawalMutationStop::AfterAggregateStore
    );
    assert_eq!(st.aggregate, 300);
    assert_eq!(BRIDGE2_SERIALIZED_FIELD_COUNT, 15);
}

#[test]
fn canonical_arbitrum_contracts_and_bridge2_balance_guard() {
    use bridge::{
        canonical_bridge2_address, canonical_usdc2_address, debit_bridge2_balance,
        embedded_contract_by_key, BRIDGE2_ALL_15_FIELD_NAMES, BRIDGE2_DEPOSIT_RING_STRIDE,
        BRIDGE2_MAINNET_ADDRESS, BRIDGE2_MAINNET_KEY, BRIDGE2_OK_DISCRIMINANT,
        BRIDGE2_TESTNET_ADDRESS, BRIDGE2_TESTNET_KEY, BRIDGE2_WITHDRAWAL_BALANCE_BUG_MSG,
        USDC2_MAINNET_ADDRESS, USDC2_MAINNET_KEY, USDC2_TESTNET_ADDRESS, USDC2_TESTNET_KEY,
    };

    assert_eq!(
        canonical_bridge2_address(ChainName::Mainnet),
        Some(BRIDGE2_MAINNET_ADDRESS)
    );
    assert_eq!(
        canonical_bridge2_address(ChainName::Testnet),
        Some(BRIDGE2_TESTNET_ADDRESS)
    );
    assert_eq!(canonical_bridge2_address(ChainName::Sandbox), None);
    assert_eq!(canonical_bridge2_address(ChainName::Local), None);

    assert_eq!(
        canonical_usdc2_address(ChainName::Mainnet),
        Some(USDC2_MAINNET_ADDRESS)
    );
    assert_eq!(
        canonical_usdc2_address(ChainName::Testnet),
        Some(USDC2_TESTNET_ADDRESS)
    );
    assert_eq!(
        embedded_contract_by_key(BRIDGE2_MAINNET_KEY),
        Some(BRIDGE2_MAINNET_ADDRESS)
    );
    assert_eq!(
        embedded_contract_by_key(BRIDGE2_TESTNET_KEY),
        Some(BRIDGE2_TESTNET_ADDRESS)
    );
    assert_eq!(
        embedded_contract_by_key(USDC2_MAINNET_KEY),
        Some(USDC2_MAINNET_ADDRESS)
    );
    assert_eq!(
        embedded_contract_by_key(USDC2_TESTNET_KEY),
        Some(USDC2_TESTNET_ADDRESS)
    );
    assert_eq!(embedded_contract_by_key("Bridge2Sandbox"), None);

    assert_eq!(BRIDGE2_ALL_15_FIELD_NAMES.len(), 15);
    assert_eq!(BRIDGE2_ALL_15_FIELD_NAMES[0], "eth_id_to_deposit_votes");
    assert_eq!(BRIDGE2_ALL_15_FIELD_NAMES[11], "bal");
    assert_eq!(BRIDGE2_DEPOSIT_RING_STRIDE, 0x68);
    assert_eq!(BRIDGE2_OK_DISCRIMINANT, 0x1a2);

    let mut bal = 1_000_000u64;
    assert_eq!(debit_bridge2_balance(&mut bal, 400_000), Ok(600_000));
    assert_eq!(bal, 600_000);
    assert_eq!(
        debit_bridge2_balance(&mut bal, 600_001),
        Err(BRIDGE2_WITHDRAWAL_BALANCE_BUG_MSG)
    );
    assert_eq!(bal, 600_000);
}
