use node115_base::api_url::ApiUrlKind;
use node115_base::bucket_guard::{BucketGuard, BucketTimeError, MAX_FAST_PATH_MILLIS};
use node115_base::build_mode::BuildMode;
use node115_base::cid::Cid;
use node115_base::guards::{AlreadySetError, CGuard, EmaTracker, SingletonSet};
use node115_base::lock_id::{
    CodeLocation, LockId, LockLocation, LockOrderWitness, LockOrderingViolation,
};
use node115_base::log_settings::{
    Crate, LogLevel, LogSettings, PhraseCheckError, Signature, ZipInnerArgs,
};
use node115_base::short_string::{MAX_INLINE_LEN, short_string_pack_rec, try_pack_short_string};
use node115_base::time::{
    HourDecodeError, MAX_EXTENDED_DAY_SECS, MAX_U8_HOUR_SECS, NANOS_PER_SEC, TimeDecodeError,
    hour_from_secs_of_day, split_unix_day_seconds,
};

#[test]
fn cid_hex_and_bytes_match_node115_rodata() {
    for cid in Cid::ALL {
        assert_eq!(Cid::from_name(cid.name()), Some(cid));
        let hex = cid.address_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 42);
        let decoded: Vec<u8> = (0..20)
            .map(|i| u8::from_str_radix(&hex[2 + i * 2..4 + i * 2], 16).unwrap())
            .collect();
        assert_eq!(decoded.as_slice(), &cid.address_bytes());
    }
    assert_eq!(Cid::from_name("UnknownCid"), None);
}

#[test]
fn api_url_and_build_mode_match_node115_literals() {
    assert_eq!(
        ApiUrlKind::Mainnet.endpoint("/info"),
        "https://api.hyperliquid.xyz/info"
    );
    assert_eq!(
        ApiUrlKind::Testnet.endpoint("exchange"),
        "https://api.hyperliquid-testnet.xyz/exchange"
    );
    assert_eq!(
        ApiUrlKind::WebSandbox.endpoint("/ws"),
        "http://localhost:3001/ws"
    );
    for mode in [BuildMode::Debug, BuildMode::Release, BuildMode::RunClient] {
        assert_eq!(BuildMode::parse(mode.as_str()), Some(mode));
    }
    assert_eq!(BuildMode::parse("staging"), None);
}

#[test]
fn time_unix_day_conversion_and_boundaries() {
    // 1970-01-01T00:00:00Z -> packed date 1970-01-01, 0 secs of day
    let epoch = split_unix_day_seconds(0, 0).unwrap();
    assert_eq!(epoch.secs_of_day, 0);
    assert_ne!(epoch.packed_date, 0);

    // 1970-01-02T01:02:03.999999999Z
    let next = split_unix_day_seconds(86_400 + 3_723, NANOS_PER_SEC - 1).unwrap();
    assert_eq!(next.secs_of_day, 3_723);
    assert_ne!(next.packed_date, epoch.packed_date);

    assert_eq!(
        split_unix_day_seconds(0, NANOS_PER_SEC),
        Err(TimeDecodeError::NanosOutOfRange)
    );
    assert_eq!(
        split_unix_day_seconds(1u64 << 32, 0),
        Err(TimeDecodeError::SecsExceedsU32)
    );
}

#[test]
fn guards_enforce_node115_invariants() {
    let guard = CGuard::new();
    assert_eq!(guard.get(), None);
    assert_eq!(guard.try_set(42u32), Ok(()));
    assert_eq!(guard.try_set(99u32), Err(AlreadySetError));
    assert_eq!(guard.get(), Some(&42));

    let mut set = SingletonSet::new();
    assert!(set.try_register("abci").is_ok());
    let err = set.try_register("abci").unwrap_err();
    assert_eq!(err, "SingletonSet could not register abci");
    assert_eq!(set.len(), 1);

    let mut ema = EmaTracker::new(0.5);
    assert_eq!(ema.try_value(), None);
    ema.update(10.0, 1.0);
    assert_eq!(ema.value(), 10.0);
    ema.update(20.0, 1.0);
    // (10*0.5 + 20) / (1*0.5 + 1) = 25 / 1.5
    assert!((ema.value() - (25.0 / 1.5)).abs() < 1e-12);
}

#[test]
#[should_panic(expected = "assertion failed: self.denom > 0.")]
fn ema_panics_when_denom_is_zero() {
    let ema = EmaTracker::new(0.5);
    let _ = ema.value();
}

#[test]
fn linked_foundation_micro_crates_compose_cleanly() {
    assert_eq!(node115_base::billion_remainder::remainder(1_000_000_042), 42);
    assert_eq!(
        node115_base::three_digit_decimal::parse_three_digit_ascii(b"123"),
        123
    );
}

#[test]
fn short_string_pack_rec_matches_node115_little_endian_contract() {
    assert_eq!(short_string_pack_rec(b"", 0), 0);
    assert_eq!(short_string_pack_rec(b"A", 0), 0x41);
    assert_eq!(short_string_pack_rec(b"ABCD", 0), 0x4443_4241);
    let max_16 = "0123456789abcdef";
    assert_eq!(max_16.len(), MAX_INLINE_LEN);
    let expected = u128::from_le_bytes(*b"0123456789abcdef");
    assert_eq!(try_pack_short_string(max_16), Some(expected));
    assert_eq!(try_pack_short_string("0123456789abcdefg"), None);
}

#[test]
fn bucket_guard_and_hour_from_secs_match_node115_bounds() {
    let mut guard = BucketGuard::new(60_000);
    assert_eq!(guard.bucket_start_millis(0), 0);
    assert_eq!(guard.bucket_start_millis(u64::MAX), u64::MAX);
    assert_eq!(
        guard.bucket_start_time(u64::MAX),
        Err(BucketTimeError::OverflowedMillis)
    );
    let t = guard.bucket_start_time(1_441).unwrap();
    // 1_441 * 60_000 ms = 86_460_000 ms = 1 day + 60s
    assert_eq!(t.secs_of_day, 60);
    assert_eq!(t.subsec_nanos, 0);

    let subsec_guard = BucketGuard::new(1_250);
    let t2 = subsec_guard.bucket_start_time(1).unwrap();
    assert_eq!(t2.secs_of_day, 1);
    assert_eq!(t2.subsec_nanos, 250_000_000);

    let too_large = BucketGuard::new(MAX_FAST_PATH_MILLIS + 1);
    assert_eq!(
        too_large.bucket_start_time(1),
        Err(BucketTimeError::MillisOutOfRange)
    );

    assert!(guard.guard(60_000));
    assert!(!guard.guard(119_999));
    assert!(guard.guard(120_000));

    assert_eq!(hour_from_secs_of_day(0), Ok(0));
    assert_eq!(hour_from_secs_of_day(86_399), Ok(23));
    assert_eq!(hour_from_secs_of_day(MAX_EXTENDED_DAY_SECS - 1), Ok(24));
    assert_eq!(
        hour_from_secs_of_day(MAX_EXTENDED_DAY_SECS),
        Err(HourDecodeError::ExceedsExtendedDayWindow)
    );
    assert_eq!(
        hour_from_secs_of_day(MAX_U8_HOUR_SECS),
        Err(HourDecodeError::ExceedsU8HourRange)
    );
}

#[test]
fn base_debug_structs_and_enums_format_binary_verified_fields() {
    assert_eq!(Crate::ALL.len(), 13);
    assert_eq!(format!("{:?}", Crate::Base), "Base");
    assert_eq!(format!("{:?}", Crate::EvmRpc), "EvmRpc");
    assert_eq!(
        format!("{:?}", PhraseCheckError::ExpectedPhraseNotFound),
        "ExpectedPhraseNotFound"
    );
    let loc = CodeLocation {
        fln: "base/src/lock_id.rs",
        line: 42,
    };
    assert!(format!("{loc:?}").contains("CodeLocation") && format!("{loc:?}").contains("fln"));
    let lock_a = LockLocation {
        id: LockId {
            inner: "a".to_owned(),
            deadlock_detection: true,
        },
        call_location: loc,
    };
    let lock_b = LockLocation {
        id: LockId {
            inner: "b".to_owned(),
            deadlock_detection: false,
        },
        call_location: loc,
    };
    let violation = LockOrderingViolation {
        reverse_edge: (lock_b.id.clone(), lock_a.id.clone()),
        reverse_witness: LockOrderWitness {
            a_lock_code_location: loc,
            b_lock_code_location: loc,
        },
        lock_a,
        lock_b,
    };
    let rendered = format!("{violation:?}");
    assert!(rendered.contains("LockOrderingViolation"));
    assert!(rendered.contains("reverse_edge"));
    assert!(rendered.contains("reverse_witness"));
    let settings = LogSettings {
        level: LogLevel::Info,
        err_fln: "err.log".to_owned(),
        stdout_fln: "out.log".to_owned(),
        throttle: true,
        log_to_stdout: false,
        n_overflow_files: 4,
        custom_dir: None,
    };
    assert!(format!("{settings:?}").contains("n_overflow_files"));
    let zip = ZipInnerArgs {
        silent: true,
        remove_orig: false,
    };
    assert!(format!("{zip:?}").contains("remove_orig"));
    let sig = Signature {
        r: [1, 2, 3, 4],
        s: [5, 6, 7, 8],
        v: 27,
    };
    assert!(format!("{sig:?}").contains("Signature"));
}

#[test]
fn runtime_utils_cover_remaining_foundation_subsystems() {
    use node115_base::runtime_utils::{
        ApiSecrets, ChainKind, DataCache, FileModTimeTracker, HttpRequestSpec, LazyMutex,
        LinerBuffer, LogHandle, ProductionGuard, QuorumPolicy, ShellSpec, SlackAlertThrottle,
        WalletAddress, daily_liner_path, fodname, format_log_prefix, sanitize_rel_segment,
        staging_rename_path,
    };
    use std::path::Path;

    let mut secrets = ApiSecrets::new();
    assert!(secrets.insert("", "x").is_err());
    assert!(secrets.insert("rpc_key", "supersecret").is_ok());
    assert_eq!(secrets.get("rpc_key"), Some("supersecret"));
    assert!(!format!("{secrets:?}").contains("supersecret"));

    assert!(ChainKind::Mainnet.is_production());
    assert!(!ChainKind::Local.is_production());
    assert!(ProductionGuard {
        chain: ChainKind::Mainnet,
        allow_unsafe_test_overrides: true,
    }
    .validate()
    .is_err());
    assert!(ProductionGuard {
        chain: ChainKind::Local,
        allow_unsafe_test_overrides: true,
    }
    .validate()
    .is_ok());

    let mut throttle = SlackAlertThrottle::new(1_000);
    assert!(throttle.should_send("oom", 10_000));
    assert!(!throttle.should_send("oom", 10_500));
    assert!(throttle.should_send("oom", 11_000));

    assert!(HttpRequestSpec::new("GET", "ftp://bad", 500).is_err());
    assert!(HttpRequestSpec::new("POST", "https://api.hyperliquid.xyz/info", 0).is_err());
    assert!(HttpRequestSpec::new("POST", "https://api.hyperliquid.xyz/info", 5_000).is_ok());

    let mut liner = LinerBuffer::new();
    assert!(liner.push_line("bad\nline").is_err());
    assert!(liner.push_line("ok-line").is_ok());
    assert_eq!(liner.lines(), &["ok-line"]);
    assert_eq!(
        daily_liner_path(Path::new("/data"), "20261127", "events.log"),
        Path::new("/data/20261127/events.log")
    );

    let mut cache = DataCache::new(500);
    cache.insert("k", 42u64, 1_000);
    assert_eq!(cache.get_fresh(&"k", 1_500), Some(&42));
    assert_eq!(cache.get_fresh(&"k", 1_501), None);

    let mut mtime = FileModTimeTracker::new();
    assert!(mtime.observe(100));
    assert!(!mtime.observe(100));
    assert!(mtime.observe(101));

    assert!(fodname(Path::new("/data"), "20261127", 24, "x").is_none());
    assert_eq!(
        fodname(Path::new("/data"), "20261127", 5, "x"),
        Some(Path::new("/data/20261127/5/x").to_path_buf())
    );
    assert!(sanitize_rel_segment("..").is_none());
    assert_eq!(sanitize_rel_segment("state.bin"), Some("state.bin"));
    assert_eq!(
        staging_rename_path(Path::new("/tmp/a.bin"), 7),
        Path::new("/tmp/a.bin.tmp.7")
    );
    assert_eq!(format_log_prefix("base", "INFO"), "[INFO][base]");

    let lazy: LazyMutex<u64> = LazyMutex::new();
    *lazy.lock_or_init(|| 10) += 5;
    assert_eq!(*lazy.lock_or_init(|| 0), 15);

    let handle = LogHandle::new(LogSettings {
        level: LogLevel::Info,
        err_fln: "e".to_owned(),
        stdout_fln: "o".to_owned(),
        throttle: false,
        log_to_stdout: true,
        n_overflow_files: 2,
        custom_dir: None,
    });
    assert_eq!(handle.state().overflow_count, 0);

    assert!(!QuorumPolicy::TWO_THIRDS.has_strict_quorum(2, 3));
    assert!(QuorumPolicy::TWO_THIRDS.has_strict_quorum(7, 10));
    assert!(!QuorumPolicy::TWO_THIRDS.has_strict_quorum(0, 0));

    assert!(ShellSpec::new("", vec![]).is_err());
    assert!(ShellSpec::new("ls", vec!["-la".to_owned()]).is_ok());

    let addr = WalletAddress::parse_hex("0x0123456789abcdef0123456789abcdef01234567").unwrap();
    assert_eq!(
        addr.to_hex_lower(),
        "0x0123456789abcdef0123456789abcdef01234567"
    );
    assert!(WalletAddress::parse_hex("0x1234").is_err());
}
