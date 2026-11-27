use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroI64;

use info_api::position::{
    project_position_integers, scan_risk_candidates, DivisionWidth, EntryDivision,
    PositionIntegerObservation, RiskCandidateRow, RiskCandidateStop,
};
use info_api::request::{
    parse_info_request_kind, FileSnapshotKind, InfoRequestKind, RequestParseError,
    ALL_INFO_REQUEST_KINDS, INFO_REQUEST_VARIANT_COUNT,
};
use info_api::response::{
    format_replica_response_json, write_raw_json_entry, L4SnapshotOptions, ReplicaResponse,
};
use info_api::router::{
    check_request_access, classify_first_stage_tag, sanitize_elapsed_secs, FirstStageDecision,
    FutureResumeState, RequestAccess, SnapshotGuardWord, HANDLE_REQUEST_RATE_LIMITER,
    HTTP_STATUS_INTERNAL_ERROR, HTTP_STATUS_OK, INFO_HTTP_PATH, PANIC_RESUMED_AFTER_COMPLETION,
    PANIC_RESUMED_AFTER_PANICKING, USER_IP_INNER_SLEEP_BITS, USER_IP_INNER_SLEEP_SECS,
    WEB_INFO_SERVICE_LABEL,
};
use info_api::{INFO_SERVER_PANIC_LOCATION_COUNT, INFO_SERVER_SOURCE_PATHS};

#[test]
fn all_55_info_request_variants_round_trip_and_match_field_counts() {
    assert_eq!(INFO_SERVER_SOURCE_PATHS.len(), 7);
    assert_eq!(INFO_SERVER_PANIC_LOCATION_COUNT, 43);
    assert_eq!(ALL_INFO_REQUEST_KINDS.len(), INFO_REQUEST_VARIANT_COUNT);
    assert_eq!(INFO_REQUEST_VARIANT_COUNT, 55);

    for (idx, kind) in ALL_INFO_REQUEST_KINDS.into_iter().enumerate() {
        assert_eq!(usize::from(kind.discriminant()), idx);
        let wire = kind.as_wire_name();
        assert_eq!(InfoRequestKind::from_wire_name(wire), Some(kind));
        assert_eq!(kind.serialized_map_entries(), 1 + kind.payload_fields().len());

        let json = format!(r#"{{"type":"{wire}","extra":{{"nested":[1,true,null,"ok"]}}}}"#);
        assert_eq!(parse_info_request_kind(json.as_bytes()), Ok(kind));
    }

    assert_eq!(
        InfoRequestKind::FileSnapshot.payload_fields(),
        &["request", "outPath", "includeHeightInOutput"]
    );
    assert_eq!(
        InfoRequestKind::SpotClearinghouseState.payload_fields(),
        &["user", "ignorePortfolioMargin"]
    );
    assert_eq!(
        InfoRequestKind::SettledOutcome.payload_fields(),
        &["outcome", "only_use_db"]
    );
    assert_eq!(
        InfoRequestKind::SettledQuestion.payload_fields(),
        &["question", "only_use_db"]
    );
    assert_eq!(
        FileSnapshotKind::from_wire_name("referrerStates"),
        Some(FileSnapshotKind::ReferrerStates)
    );
    assert_eq!(
        FileSnapshotKind::from_wire_name("l4Snapshots"),
        Some(FileSnapshotKind::L4Snapshots)
    );
    assert_eq!(
        FileSnapshotKind::L4Snapshots.payload_fields(),
        &["includeUsers", "includeTriggerOrders"]
    );
}

#[test]
fn request_parser_uses_strict_scanner_and_error_position() {
    // Escaped string value decoded via node115-json-string-scanner
    assert_eq!(
        parse_info_request_kind(br#"{"user":"0x1","type":"me\u0074a"}"#),
        Ok(InfoRequestKind::Meta)
    );

    // Unknown variant
    assert_eq!(
        parse_info_request_kind(br#"{"type":"nonexistentQuery"}"#),
        Err(RequestParseError::UnknownVariant(
            "nonexistentQuery".to_string()
        ))
    );

    // Missing type field
    assert_eq!(
        parse_info_request_kind(br#"{"user":"0xabc"}"#),
        Err(RequestParseError::MissingTypeField)
    );

    // Unescaped control byte on line 2 reports scanner code 16 and exact 1-based line / 0-based col
    let bad = b"{\n\"type\":\"me\x01ta\"}";
    assert_eq!(
        parse_info_request_kind(bad),
        Err(RequestParseError::Syntax {
            scanner_code: Some(16),
            line: 2,
            column: 11,
        })
    );
}

#[test]
fn router_timing_localhost_future_and_snapshot_guard_invariants() {
    assert_eq!(INFO_HTTP_PATH, "/info");
    assert_eq!(WEB_INFO_SERVICE_LABEL, "Web /info");
    assert_eq!(HANDLE_REQUEST_RATE_LIMITER, "handle_request_rate_limiter");
    assert_eq!(HTTP_STATUS_OK, 200);
    assert_eq!(HTTP_STATUS_INTERNAL_ERROR, 500);
    assert_eq!(USER_IP_INNER_SLEEP_SECS.to_bits(), USER_IP_INNER_SLEEP_BITS);

    assert_eq!(sanitize_elapsed_secs(0.125), 0.125);
    assert_eq!(sanitize_elapsed_secs(-0.001), 0.0);
    assert_eq!(sanitize_elapsed_secs(f64::INFINITY), 0.0);
    assert_eq!(sanitize_elapsed_secs(f64::NAN), 0.0);

    let v4_lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6_lo = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    assert_eq!(
        check_request_access(InfoRequestKind::FileSnapshot, v4_lo),
        RequestAccess::Allowed
    );
    assert_eq!(
        check_request_access(InfoRequestKind::FileSnapshot, v6_lo),
        RequestAccess::Allowed
    );
    assert_eq!(
        check_request_access(InfoRequestKind::FileSnapshot, remote),
        RequestAccess::RejectedNotLocalhost
    );
    assert_eq!(
        check_request_access(InfoRequestKind::Meta, remote),
        RequestAccess::Allowed
    );

    assert_eq!(FutureResumeState::Initial.resume_panic_message(), None);
    assert_eq!(
        FutureResumeState::Completed.resume_panic_message(),
        Some(PANIC_RESUMED_AFTER_COMPLETION)
    );
    assert_eq!(
        FutureResumeState::Panicked.resume_panic_message(),
        Some(PANIC_RESUMED_AFTER_PANICKING)
    );

    assert_eq!(
        classify_first_stage_tag(0),
        Some(FirstStageDecision::SkipSecondEmitTag2)
    );
    assert_eq!(
        classify_first_stage_tag(1),
        Some(FirstStageDecision::PollSecondQuery)
    );
    assert_eq!(
        classify_first_stage_tag(2),
        Some(FirstStageDecision::ShortCircuitTag3)
    );
    assert_eq!(
        classify_first_stage_tag(3),
        Some(FirstStageDecision::ShortCircuitTag3)
    );
    assert_eq!(
        classify_first_stage_tag(4),
        Some(FirstStageDecision::PendingContinuation3)
    );
    assert_eq!(classify_first_stage_tag(5), None);

    let g0 = SnapshotGuardWord(0);
    let g1 = g0.try_acquire_fast().unwrap();
    assert_eq!(g1.0, 16);
    let (g_back, wake) = g1.release();
    assert_eq!(g_back.0, 0);
    assert!(!wake);

    // Disallowed bit 3 forces slow path
    assert_eq!(SnapshotGuardWord(8).try_acquire_fast(), None);
    // Reader limit forces slow path
    assert_eq!(
        SnapshotGuardWord(SnapshotGuardWord::READER_LIMIT).try_acquire_fast(),
        None
    );
    // Wake condition: (old & !13) == 18 -> old = 18 triggers wake on release
    let (after, should_wake) = SnapshotGuardWord(18).release();
    assert_eq!(after.0, 2);
    assert!(should_wake);
}

#[test]
fn position_projection_and_replica_response_json_integration() {
    let obs = project_position_integers(NonZeroI64::new(3).unwrap(), 7, 7);
    assert_eq!(
        obs,
        PositionIntegerObservation::Normal {
            product_word: 21,
            pnl_word: 14,
            division: Some(EntryDivision {
                quotient: 2,
                remainder: 1,
                width: DivisionWidth::Narrow32,
            }),
        }
    );

    let rows = [
        RiskCandidateRow {
            tag: 0,
            lower: 3_000_000,
            upper: 0,
            word_10: 0,
            byte_18: 1,
        },
        RiskCandidateRow {
            tag: 1,
            lower: 1_000_000,
            upper: 3_000_000,
            word_10: 0,
            byte_18: 1,
        },
    ];
    assert_eq!(
        scan_risk_candidates(&rows, -1_000_000, 0, 1, 0),
        Ok(Some(2.0))
    );
    assert_eq!(
        scan_risk_candidates(&rows, 1, 0, 1, 22),
        Err(RiskCandidateStop::Decimals)
    );

    let hash = [0xabu8; 32];
    assert_eq!(
        format_replica_response_json::<&str>(ReplicaResponse::Null, write_raw_json_entry).unwrap(),
        "null"
    );
    let hash_json =
        format_replica_response_json::<&str>(ReplicaResponse::Hash(&hash), write_raw_json_entry)
            .unwrap();
    assert_eq!(
        hash_json,
        format!(r#"{{"Hash":"0x{}"}}"#, "ab".repeat(32))
    );

    let full_rows = [(hash, vec![r#"{"ok":true}"#])];
    let full_json =
        format_replica_response_json(ReplicaResponse::Full(&full_rows), write_raw_json_entry)
            .unwrap();
    assert_eq!(
        full_json,
        format!(r#"{{"Full":[["0x{}",[{{"ok":true}}]]]}}"#, "ab".repeat(32))
    );

    let opts = L4SnapshotOptions {
        include_users: true,
        include_trigger_orders: false,
    };
    assert!(opts.include_users && !opts.include_trigger_orders);
}

#[test]
fn position_boundary_overflow_and_request_corruption_cases() {
    // Negative mark word -> MarkOrProductBoundary
    assert_eq!(
        project_position_integers(NonZeroI64::new(1).unwrap(), u64::MAX, 0),
        PositionIntegerObservation::MarkOrProductBoundary
    );
    // Signed multiplication overflow -> MarkOrProductBoundary
    assert_eq!(
        project_position_integers(NonZeroI64::new(i64::MAX).unwrap(), 2, 0),
        PositionIntegerObservation::MarkOrProductBoundary
    );
    // Negative entry word -> EntrySignBoundary
    assert_eq!(
        project_position_integers(NonZeroI64::new(2).unwrap(), 10, u64::MAX),
        PositionIntegerObservation::EntrySignBoundary
    );
    // Entry == 0 -> division None, pnl 0
    assert_eq!(
        project_position_integers(NonZeroI64::new(-4).unwrap(), 5, 0),
        PositionIntegerObservation::Normal {
            product_word: (-20i64) as u64,
            pnl_word: 0,
            division: None,
        }
    );
    // Wide64 division path (entry_word > u32::MAX)
    let big_entry = u64::from(u32::MAX) + 10;
    let wide = project_position_integers(NonZeroI64::new(2).unwrap(), 10, big_entry);
    match wide {
        PositionIntegerObservation::Normal {
            division: Some(div),
            ..
        } => {
            assert_eq!(div.width, DivisionWidth::Wide64);
            assert_eq!(div.quotient, big_entry / 2);
            assert_eq!(div.remainder, big_entry % 2);
        }
        other => panic!("expected Wide64 division, got {other:?}"),
    }
    // Entry < magnitude -> division None
    match project_position_integers(NonZeroI64::new(10).unwrap(), 10, 5) {
        PositionIntegerObservation::Normal { division, .. } => assert_eq!(division, None),
        other => panic!("expected Normal with division None, got {other:?}"),
    }

    // Non-object / truncated / invalid JSON syntax rejected
    assert!(parse_info_request_kind(b"[]").is_err());
    assert!(parse_info_request_kind(b"").is_err());
    assert!(parse_info_request_kind(br#"{"type":123}"#).is_err());
    assert!(parse_info_request_kind(br#"{"type":"meta""#).is_err());

    // Non-loopback IPv6 rejected for FileSnapshot
    let remote_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(
        check_request_access(InfoRequestKind::FileSnapshot, remote_v6),
        RequestAccess::RejectedNotLocalhost
    );
}
