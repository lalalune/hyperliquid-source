use node115_base::api_url::ApiUrlKind;
use node115_base::build_mode::BuildMode;
use node115_base::cid::Cid;
use node115_base::guards::{AlreadySetError, CGuard, EmaTracker, SingletonSet};
use node115_base::time::{NANOS_PER_SEC, TimeDecodeError, split_unix_day_seconds};

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
