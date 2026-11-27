use action_wire::{
    eip712::{
        domain_separator_u64, find_user_signed_schema, signing_digest, AbstractionKind,
        ChainSelector, Eip712FieldValue, ProposalCategory, VoteChoice, USER_SIGNED_SCHEMAS,
    },
    error_display::{
        decode_template, known_wire_error_text, render_template, TemplateDecodeError,
        TemplatePiece, ACTION_SUCCESS_TAG, TAG_NONCE_TOO_LOW,
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
