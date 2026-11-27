use action_wire::{
    eip712::{
        domain_separator_u64, find_user_signed_schema, signing_digest, AbstractionKind,
        ChainSelector, Eip712FieldValue, ProposalCategory, VoteChoice, USER_SIGNED_SCHEMAS,
    },
    error_display::{
        decode_template, known_wire_error_text, render_template, TemplateDecodeError,
        TemplatePiece, ACTION_SUCCESS_TAG, TAG_NONCE_TOO_LOW,
    },
    rmp_signable::{
        check_user_outcome_entry, connection_id, connection_id_preimage, fold_action_result,
        ActionEnvelopeFold, DelayedActionRecord, UserOutcomeEntryReject,
        ACTION_DELAYER_FIELD_COUNT, ENVELOPE_ERR_BYTE, ENVELOPE_OK_BYTE,
        USER_OUTCOME_BLOCKED_SUBCODE, USER_OUTCOME_BLOCKED_TAG, USER_OUTCOME_DISABLED_TAG,
        USER_OUTCOME_UNKNOWN_USER_TAG,
    },
    signed_action_four_field::{
        encode_body as encode_four_field, ContainerMode, FourFieldAction, HyperliquidChain,
    },
    usd_class_transfer::{
        encode_body as encode_usd_class_transfer, ContainerMode as UsdMode,
        HyperliquidChain as UsdChain, UsdClassTransferAction,
    },
    variants::{
        tag_to_index, variant_by_tag, variant_by_wire_name, ACTION_TAG_BASE, ACTION_TAG_MAX,
        ACTION_VARIANTS, VOTE_GLOBAL_NICHE_INDEX,
    },
};

#[test]
fn all_92_action_variants_and_vote_global_niche_rule_match_crosswalk() {
    assert_eq!(ACTION_VARIANTS.len(), 92);
    for (i, info) in ACTION_VARIANTS.iter().enumerate() {
        assert_eq!(info.index, i);
        assert_eq!(info.canonical_tag, ACTION_TAG_BASE + i as u64);
        assert_eq!(variant_by_wire_name(info.wire_name).unwrap().index, i);
    }
    // Any tag < 0x86 maps to VoteGlobal (index 20).
    for tag in [0u64, 1, 0x42, 0x85] {
        assert_eq!(tag_to_index(tag), Some(VOTE_GLOBAL_NICHE_INDEX));
        assert_eq!(variant_by_tag(tag).unwrap().variant_name, "VoteGlobal");
    }
    // Tag 0xd1 -> index 75 (SendToEvmWithData).
    assert_eq!(
        variant_by_tag(0xd1).unwrap().variant_name,
        "SendToEvmWithData"
    );
    // Tag 0xdd -> index 87 (VoteAbciDigest).
    assert_eq!(variant_by_tag(0xdd).unwrap().variant_name, "VoteAbciDigest");
    // Out of range tags return None.
    assert_eq!(tag_to_index(ACTION_TAG_MAX + 1), None);
}

#[test]
fn eip712_domain_and_usd_send_digest_are_deterministic_and_sensitive() {
    assert_eq!(USER_SIGNED_SCHEMAS.len(), 38);
    assert_eq!(ChainSelector::Mainnet.label(), "Mainnet");
    assert_eq!(VoteChoice::Abstain.label(), "abstain");
    assert_eq!(ProposalCategory::Constitutional.label(), "constitutional");
    assert_eq!(AbstractionKind::PortfolioMargin.label(), "portfolioMargin");

    let schema = find_user_signed_schema("UsdSend", false).unwrap();
    assert_eq!(schema.wrapper_va, 0x44338b0);

    let mut cid = [0u8; 32];
    cid[24..32].copy_from_slice(&42161u64.to_be_bytes());
    let d1 = signing_digest(
        cid,
        schema.encode_type,
        &[
            Eip712FieldValue::String(ChainSelector::Mainnet.label()),
            Eip712FieldValue::String("0x0000000000000000000000000000000000000001"),
            Eip712FieldValue::String("100"),
            Eip712FieldValue::Uint64(1_700_000_000_000),
        ],
    );
    // Changing chain id or amount must change the digest.
    let mut cid2 = cid;
    cid2[31] ^= 1;
    let d2 = signing_digest(
        cid2,
        schema.encode_type,
        &[
            Eip712FieldValue::String(ChainSelector::Mainnet.label()),
            Eip712FieldValue::String("0x0000000000000000000000000000000000000001"),
            Eip712FieldValue::String("100"),
            Eip712FieldValue::Uint64(1_700_000_000_000),
        ],
    );
    assert_ne!(d1, d2);
    assert_ne!(domain_separator_u64(42161), domain_separator_u64(421614));
}

#[test]
fn error_display_template_decoder_handles_short_long_and_arg_opcodes() {
    assert_eq!(ACTION_SUCCESS_TAG, 418);
    assert_eq!(
        known_wire_error_text(TAG_NONCE_TOO_LOW),
        Some("Invalid nonce: nonce too low {} < {}")
    );
    // Short literal "hi " (3), arg (0xc0), long literal " world" (0x80, len 6 le), end (0x00).
    let mut tmpl = vec![3, b'h', b'i', b' ', 0xc0, 0x80, 6, 0];
    tmpl.extend_from_slice(b" world");
    tmpl.push(0x00);
    let pieces = decode_template(&tmpl).unwrap();
    assert_eq!(
        pieces,
        vec![
            TemplatePiece::Literal(b"hi "),
            TemplatePiece::Argument,
            TemplatePiece::Literal(b" world"),
        ]
    );
    assert_eq!(render_template(&tmpl, &["42"]).unwrap(), "hi 42 world");

    // Unknown opcode rejected.
    assert_eq!(
        decode_template(&[0x99]),
        Err(TemplateDecodeError::UnexpectedOpcode(0x99))
    );
}

#[test]
fn micro_crate_codecs_compose_cleanly() {
    let mut cid = [0u8; 32];
    cid[0..8].copy_from_slice(&42161u64.to_le_bytes());

    let four = encode_four_field(
        &[],
        ContainerMode::Map,
        FourFieldAction {
            tag_key: "type",
            variant: "cDeposit",
            signature_chain_id: cid,
            chain: HyperliquidChain::Mainnet,
            wei: 1_000_000,
            nonce: 12345,
        },
    );
    assert!(!four.is_empty());

    let uct = encode_usd_class_transfer(
        &[],
        UsdMode::Map,
        UsdClassTransferAction {
            tag_key: "type",
            variant: "usdClassTransfer",
            signature_chain_id: cid,
            chain: UsdChain::Mainnet,
            amount: b"50",
            to_perp: true,
            nonce: 99,
        },
    );
    assert!(!uct.is_empty());
}

#[test]
fn rmp_signable_connection_id_matches_node115_layout_rules() {
    let payload = [0x81, 0xa4, b't', b'y', b'p', b'e', 0xa4, b'n', b'o', b'o', b'p'];
    let nonce = 0x0102_0304_0506_0708u64;
    let vault = [0xab; 20];
    let expires = 0x1122_3344_5566_7788u64;

    // No vault, no expires_after: payload || be64(nonce) || 0x00.
    let p_plain = connection_id_preimage(&payload, nonce, None, None);
    assert_eq!(p_plain.len(), payload.len() + 8 + 1);
    assert_eq!(&p_plain[payload.len()..payload.len() + 8], &nonce.to_be_bytes());
    assert_eq!(p_plain[payload.len() + 8], 0x00);

    // With vault, no expires_after: payload || be64(nonce) || 0x01 || vault[20].
    let p_vault = connection_id_preimage(&payload, nonce, Some(vault), None);
    assert_eq!(p_vault.len(), payload.len() + 8 + 1 + 20);
    assert_eq!(p_vault[payload.len() + 8], 0x01);
    assert_eq!(&p_vault[payload.len() + 9..payload.len() + 29], &vault);

    // With vault and expires_after: ... || 0x00 || be64(expires).
    let p_exp = connection_id_preimage(&payload, nonce, Some(vault), Some(expires));
    assert_eq!(p_exp.len(), payload.len() + 8 + 1 + 20 + 1 + 8);
    assert_eq!(p_exp[payload.len() + 29], 0x00);
    assert_eq!(&p_exp[payload.len() + 30..], &expires.to_be_bytes());

    // Connection IDs must differ across vault / expires_after variations.
    let id_plain = connection_id(&payload, nonce, None, None);
    let id_vault = connection_id(&payload, nonce, Some(vault), None);
    let id_exp = connection_id(&payload, nonce, Some(vault), Some(expires));
    assert_ne!(id_plain, id_vault);
    assert_ne!(id_vault, id_exp);
}

#[test]
fn vault_transfer_withdraw3_fold_user_outcome_and_delayer_match_node115() {
    // Success tag 0x1a2 folds to 0x0e (0x283c6b0 / 0x246cd10).
    let mut ok_slot = [0u8; 0x70];
    ok_slot[0..2].copy_from_slice(&ACTION_SUCCESS_TAG.to_le_bytes());
    assert_eq!(
        fold_action_result(&ok_slot),
        ActionEnvelopeFold::Ok {
            tag_byte: ENVELOPE_OK_BYTE,
        }
    );

    // Error tag != 0x1a2 folds to 0x0f with full 0x70-byte error copy.
    let mut err_slot = [0x55u8; 0x70];
    err_slot[0..2].copy_from_slice(&TAG_NONCE_TOO_LOW.to_le_bytes());
    assert_eq!(
        fold_action_result(&err_slot),
        ActionEnvelopeFold::Err {
            tag_byte: ENVELOPE_ERR_BYTE,
            error_tag: TAG_NONCE_TOO_LOW,
            payload: err_slot,
        }
    );

    // user_outcome.rs entry guard precedence: disabled (0x92) -> blocked (0x193/7) -> unknown user (0x15).
    assert_eq!(
        check_user_outcome_entry(false, true, false),
        Err(UserOutcomeEntryReject::Disabled {
            tag: USER_OUTCOME_DISABLED_TAG
        })
    );
    assert_eq!(
        check_user_outcome_entry(true, true, false),
        Err(UserOutcomeEntryReject::Blocked {
            tag: USER_OUTCOME_BLOCKED_TAG,
            subcode: USER_OUTCOME_BLOCKED_SUBCODE,
        })
    );
    assert_eq!(
        check_user_outcome_entry(true, false, false),
        Err(UserOutcomeEntryReject::UnknownUser {
            tag: USER_OUTCOME_UNKNOWN_USER_TAG
        })
    );
    assert_eq!(check_user_outcome_entry(true, false, true), Ok(()));

    // ActionDelayer schema field count & record representation.
    assert_eq!(ACTION_DELAYER_FIELD_COUNT, 6);
    let rec = DelayedActionRecord {
        id: 1,
        action_index: 14,
        is_frontend: true,
        expires_after: Some(1_700_000_000_000),
        delay_scale: 1,
    };
    assert_eq!(rec.action_index, 14);
}
