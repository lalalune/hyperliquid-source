use std::collections::{BTreeMap, BTreeSet};

use dex_registry::{
    date_time_display::{Date, Time},
    disabled_record::Timestamp,
    disabled_state_codec::DisabledState,
    format_address_hex,
    registry::{DexRegistry, Pdi, RegistryError},
    schema::{DexKind, DexMetadata, Hip3Limits, Hip3Schema, Hip3State, WireMode},
    sub_deployers::{encode_sub_deployer_element, Hip3DeployAction, SubDeployers},
};

fn ts() -> Timestamp {
    Timestamp {
        date: Date::new(2026, 104).unwrap(),
        time: Time::new(12 * 3600, 0).unwrap(),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn all_23_hip3_deploy_actions_match_node115_name_table_bytes() {
    // Exact pinned bytes from research/work-items/dex-registry-sub-deployers-115/name-table.tsv.
    let expected: &[(u8, &str)] = &[
        (0, "81a86869703353746172ae6d6f64696679417070726f76616c"),
        (
            1,
            "81a86869703353746172d9206d6f646966794261636b73746f704c697175696461746f72417070726f76616c",
        ),
        (2, "81a86869703353746172ad7365745265647563654f6e6c79"),
        (3, "81a86869703353746172a663616e63656c"),
        (4, "81a86869703353746172a963616e63656c416c6c"),
        (5, "81a86869703353746172a56f72646572"),
        (6, "81a86869703353746172a973656e644173736574"),
        (7, "81a86869703353746172a97365744f7261636c65"),
        (8, "ad72656769737465724173736574"),
        (9, "a97365744f7261636c65"),
        (10, "b1696e736572744d617267696e5461626c65"),
        (11, "af736574466565526563697069656e74"),
        (12, "ab68616c7454726164696e67"),
        (13, "b17365744d617267696e5461626c65496473"),
        (14, "b37365744f70656e496e74657265737443617073"),
        (15, "b573657446756e64696e674d756c7469706c69657273"),
        (16, "ae7365744d617267696e4d6f646573"),
        (17, "af7365744465706c6f79657246656573"),
        (18, "b773657446756e64696e67496e7465726573745261746573"),
        (19, "aa64697361626c65446578"),
        (20, "b173657450657270416e6e6f746174696f6e"),
        (21, "b46d69677261746544657851756f7465546f6b656e"),
        (22, "b073657446756e64696e67436c616d7073"),
    ];
    assert_eq!(Hip3DeployAction::ALL.len(), expected.len());
    for &(tag, want_hex) in expected {
        let action = Hip3DeployAction::from_tag(tag).unwrap();
        let mut buf = Vec::new();
        action.encode_msgpack(&mut buf);
        assert_eq!(hex_of(&buf), want_hex, "tag {tag} ({action:?})");
    }
    assert_eq!(Hip3DeployAction::from_tag(23), None);
}

#[test]
fn sub_deployer_element_encodes_pair_with_lowercase_0x_addresses() {
    let addr = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xaa, 0xbb,
    ];
    assert_eq!(
        format_address_hex(&addr),
        "0x0123456789abcdef00112233445566778899aabb"
    );
    let mut set = BTreeSet::new();
    set.insert(addr);
    let mut out = Vec::new();
    encode_sub_deployer_element(&mut out, Hip3DeployAction::SetOracle, &set);
    // 0x92 (pair), 0xa9 "setOracle", 0x91 (1-element array), 0xd9 0x2a (42-byte str), "0x..."
    assert_eq!(out[0], 0x92);
    assert_eq!(&out[1..11], b"\xa9setOracle");
    assert_eq!(out[11], 0x91);
    assert_eq!(&out[12..14], &[0xd9, 42]);
    assert_eq!(&out[14..], b"0x0123456789abcdef00112233445566778899aabb");
}

#[test]
fn main_and_hip3_envelope_dynamic_field_counts_and_visitor() {
    assert_eq!(DexKind::from_name("Main"), Some(DexKind::Main));
    assert_eq!(DexKind::from_name("Hip3"), Some(DexKind::Hip3));
    assert_eq!(DexKind::from_name("main"), None);
    assert_eq!(DexKind::Main.visitor_result_word(), 0x0009);
    assert_eq!(DexKind::Hip3.visitor_result_word(), 0x0109);

    let mut sub = SubDeployers::default();
    sub.grant(Hip3DeployAction::SetOracle, [0x22; 20]);

    let hip3 = DexMetadata::Hip3 {
        limits: Hip3Limits {
            total_oi_cap2: 1_000_000,
            oi_sz_cap_per_perp: 500_000,
            max_transfer_ntl2: 250_000,
            max_under_initial_margin_transfer_ntl2: 100_000,
            daily_px_range: 50,
            max_n_users_with_positions: 10_000,
        },
        schema: Box::new(Hip3Schema {
            name: "xyz".to_string(),
            full_name: "XYZ Perps".to_string(),
            deployer: [0x11; 20],
            oracle_updater: Some([0x22; 20]),
            fee_recipient: None,
            asset_to_oi_cap: BTreeMap::from([(0, 100_000)]),
            sub_deployers: sub,
        }),
        state: Hip3State {
            last_settlement_time: ts(),
            deploy_time: ts(),
            n_reserve_deployments_used: 2,
            disabled_state: DisabledState::Na,
            m: true,
        },
        backstop_liquidator_state: Some(vec![0xc0]),
        ss: None,
        df: Some(vec![0xc3]),
    };

    assert_eq!(hip3.hip3_field_count(), Some(5));
    let mut map_bytes = Vec::new();
    hip3.encode_msgpack(WireMode::Map, &mut map_bytes);
    // 0x81, 0xa4 "Hip3", 0x85 (5-field fixmap)
    assert_eq!(&map_bytes[..7], b"\x81\xa4Hip3\x85");

    let mut arr_bytes = Vec::new();
    hip3.encode_msgpack(WireMode::Array, &mut arr_bytes);
    // 0x81, 0xa4 "Hip3", 0x95 (5-field fixarray)
    assert_eq!(&arr_bytes[..7], b"\x81\xa4Hip3\x95");
}

#[test]
fn registry_pdi_lookup_name_index_and_deployer_authorization() {
    let deployer = [0x11; 20];
    let oracle_sub = [0x22; 20];
    let stranger = [0x99; 20];

    let mut reg: DexRegistry<u64> = DexRegistry::new();
    let main = DexMetadata::Main {
        asset_to_recent_oi: vec![0x80],
        override_max_oi_per_second: vec![0xc0],
        reset_recent_oi_bucket_guard: vec![0xc0],
        assets_at_open_interest_cap: vec![0x90],
    };
    assert_eq!(reg.register_main(main, 100).unwrap(), Pdi::MAIN);

    let mut sub = SubDeployers::default();
    sub.grant(Hip3DeployAction::SetOracle, oracle_sub);
    let hip3 = DexMetadata::Hip3 {
        limits: Hip3Limits {
            total_oi_cap2: 1,
            oi_sz_cap_per_perp: 2,
            max_transfer_ntl2: 3,
            max_under_initial_margin_transfer_ntl2: 4,
            daily_px_range: 5,
            max_n_users_with_positions: 6,
        },
        schema: Box::new(Hip3Schema {
            name: "abc".to_string(),
            full_name: "ABC".to_string(),
            deployer,
            oracle_updater: None,
            fee_recipient: None,
            asset_to_oi_cap: BTreeMap::new(),
            sub_deployers: sub,
        }),
        state: Hip3State {
            last_settlement_time: ts(),
            deploy_time: ts(),
            n_reserve_deployments_used: 0,
            disabled_state: DisabledState::Na,
            m: false,
        },
        backstop_liquidator_state: None,
        ss: None,
        df: None,
    };

    let pdi1 = reg.register_hip3(hip3.clone(), 200).unwrap();
    assert_eq!(pdi1, Pdi(1));
    assert_eq!(reg.pdi_by_name(""), Some(Pdi::MAIN));
    assert_eq!(reg.pdi_by_name("abc"), Some(Pdi(1)));
    assert_eq!(reg.pdi_by_name("missing"), None);

    // Duplicate name rejected.
    assert_eq!(
        reg.register_hip3(hip3, 300),
        Err(RegistryError::DuplicateDexName("abc".to_string()))
    );

    // Out-of-bounds PDI rejected.
    assert_eq!(
        reg.get(Pdi(2)).unwrap_err(),
        RegistryError::UnknownPdi { pdi: Pdi(2), len: 2 }
    );

    // Authorization: deployer allowed for all actions, sub-deployer only for SetOracle.
    assert!(reg
        .authorize_hip3_action(pdi1, Hip3DeployAction::HaltTrading, &deployer)
        .is_ok());
    assert!(reg
        .authorize_hip3_action(pdi1, Hip3DeployAction::SetOracle, &oracle_sub)
        .is_ok());
    assert_eq!(
        reg.authorize_hip3_action(pdi1, Hip3DeployAction::HaltTrading, &oracle_sub),
        Err(RegistryError::UnauthorizedDeployer)
    );
    assert_eq!(
        reg.authorize_hip3_action(pdi1, Hip3DeployAction::SetOracle, &stranger),
        Err(RegistryError::UnauthorizedDeployer)
    );

    // Cross-DEX scan finds clearinghouse 200.
    assert!(reg.any_slot(|s| s.clearinghouse == 200));
    assert!(!reg.any_slot(|s| s.clearinghouse == 999));

    // disableDex authorization (selector 0x13, 0x469e170) & disabled-state transition.
    assert_eq!(
        reg.set_disabled_state(pdi1, &oracle_sub, DisabledState::UserDisabled, false),
        Err(RegistryError::UnauthorizedDeployer)
    );
    assert_eq!(
        reg.set_disabled_state(pdi1, &deployer, DisabledState::UserDisabled, false),
        Ok(DisabledState::Na)
    );
    // Once UserDisabled, regular actions like SetOracle are rejected with DexDisabled,
    // while DisableDex itself remains reachable for the authorized caller.
    assert_eq!(
        reg.authorize_hip3_action(pdi1, Hip3DeployAction::SetOracle, &oracle_sub),
        Err(RegistryError::DexDisabled(DisabledState::UserDisabled))
    );
    assert!(reg
        .authorize_hip3_action(pdi1, Hip3DeployAction::DisableDex, &deployer)
        .is_ok());
    // Validator override transitions to ValidatorDisabled regardless of caller.
    assert_eq!(
        reg.set_disabled_state(pdi1, &stranger, DisabledState::ValidatorDisabled, true),
        Ok(DisabledState::UserDisabled)
    );
}
