use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use global_constants::{
    aws_name_path_for_cham_dir, code_dir_for_cham_dir, parse_static_config_json, read_aws_name,
    resolve_cham_dir, static_config_file_path, AwsName, ChainDisplay, ChainName, SpotMarkKind,
    StaticConfig, StaticConfigParseError, VariantNotFound,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_temp_dir(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "hl-node115-gc-{label}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn aws_name_all_79_variants_roundtrip_and_node115_shifts() {
    assert_eq!(AwsName::COUNT, 79);
    assert_eq!(AwsName::ALL.len(), 79);
    // Node #115 specific shifts vs retired #94:
    assert_eq!(AwsName::EaTx.discriminant(), 13);
    assert_eq!(AwsName::SoloSandbox.discriminant(), 32);
    assert_eq!(AwsName::NvTestnet.discriminant(), 33);
    assert_eq!(AwsName::NvTestnet2.discriminant(), 34);
    assert_eq!(AwsName::NvMainnet3.discriminant(), 37);
    assert_eq!(AwsName::DummyNv.discriminant(), 39);
    assert_eq!(AwsName::DEFAULT_FALLBACK, AwsName::NvTestnet);

    for (idx, &variant) in AwsName::ALL.iter().enumerate() {
        assert_eq!(variant.discriminant(), idx as u8);
        assert_eq!(AwsName::from_discriminant(idx as u8), Some(variant));
        let name = variant.as_str();
        assert_eq!(variant.to_string(), name);
        assert_eq!(AwsName::from_str(name), Ok(variant));
        assert_eq!(AwsName::classify_byte(name), idx as u8);
        // Case sensitivity and boundary rejections:
        assert_eq!(AwsName::from_str(&name.to_lowercase()), Err(VariantNotFound));
        assert_eq!(AwsName::from_str(&format!("{name}x")), Err(VariantNotFound));
        assert_eq!(AwsName::classify_byte(&format!(" {name}")), 79);
    }
    assert_eq!(AwsName::from_discriminant(79), None);
    assert_eq!(AwsName::from_discriminant(255), None);
    assert_eq!(format!("{VariantNotFound:?}"), "VariantNotFound");
}

#[test]
fn aws_name_unicode_trim_and_rodata_4671d0_table() {
    // Unicode White_Space points checked in constants-static-name-flow-115:
    assert_eq!(
        AwsName::from_trimmed_str("\u{00a0}\u{1680}\u{2003}NvMainnet3\u{3000}\r\n"),
        Ok(AwsName::NvMainnet3)
    );
    assert_eq!(AwsName::from_trimmed_str("   \u{2000}\u{3000} "), Err(VariantNotFound));

    // Exact 18 variants with 1.0 in .rodata 0x4671d0, 61 others with 5.0:
    let ones: Vec<u8> = AwsName::ALL
        .iter()
        .copied()
        .filter(|v| v.rodata_4671d0_f64() == 1.0)
        .map(AwsName::discriminant)
        .collect();
    assert_eq!(
        ones,
        vec![1, 2, 9, 10, 11, 12, 13, 15, 16, 18, 20, 22, 25, 26, 35, 36, 37, 38]
    );
    assert_eq!(
        AwsName::ALL
            .iter()
            .filter(|v| v.rodata_4671d0_f64() == 5.0)
            .count(),
        61
    );

    // Exact 7 variants in 0x10078c000 bitmask:
    let masked: Vec<AwsName> = AwsName::ALL
        .iter()
        .copied()
        .filter(|v| v.is_solo_heavy_or_locker())
        .collect();
    assert_eq!(
        masked,
        vec![
            AwsName::HeavyTestnet,
            AwsName::HeavyMainnet,
            AwsName::SoloTestnet,
            AwsName::SoloMainnet,
            AwsName::LockerTestnet,
            AwsName::LockerMainnet,
            AwsName::SoloSandbox,
        ]
    );
}

#[test]
fn static_config_json_grammar_and_whitespace_mask() {
    let never = || -> AwsName { panic!("fallback should not run") };

    assert_eq!(
        parse_static_config_json(r#"{"aws_name":"SoloSandbox"}"#, never),
        Ok(AwsName::SoloSandbox)
    );
    // Externally tagged unit variant accepted by 0x1773070:
    assert_eq!(
        parse_static_config_json(r#"{"aws_name": {"EaTx": null}}"#, never),
        Ok(AwsName::EaTx)
    );
    // Sequence form accepted by 0x17771b0:
    assert_eq!(
        parse_static_config_json(r#" [ "NvMainnet2" ] "#, never),
        Ok(AwsName::NvMainnet2)
    );
    // Unknown fields ignored:
    assert_eq!(
        parse_static_config_json(
            r#"{"extra": [1, true, null, {"nested": "ok"}], "aws_name": "DummyNv", "num": -1.5e2}"#,
            never
        ),
        Ok(AwsName::DummyNv)
    );
    // Duplicate aws_name rejected:
    assert_eq!(
        parse_static_config_json(r#"{"aws_name":"Ec","aws_name":"Ea"}"#, never),
        Err(StaticConfigParseError::DuplicateField)
    );
    // Missing field invokes fallback:
    assert_eq!(
        parse_static_config_json(r#"{"other": 123}"#, || AwsName::JoinMainnet),
        Ok(AwsName::JoinMainnet)
    );
    assert_eq!(
        parse_static_config_json("[]", || AwsName::RpcMainnet2),
        Ok(AwsName::RpcMainnet2)
    );
    // Exact trailing whitespace mask 0x100002600 (9, 10, 13, 32 only):
    assert_eq!(
        parse_static_config_json("{\"aws_name\":\"Ec\"}\t\n\r ", never),
        Ok(AwsName::Ec)
    );
    for bad_ws in ["\x0b", "\x0c", "\u{00a0}", "x"] {
        let doc = format!("{{\"aws_name\":\"Ec\"}}{bad_ws}");
        assert_eq!(
            parse_static_config_json(&doc, never),
            Err(StaticConfigParseError::TrailingCharacters)
        );
    }
}

#[test]
fn static_config_filesystem_paths_and_fallbacks() {
    // Case 1: /cham exists -> selected over /hl; /code/static_config valid.
    let home = fresh_temp_dir("cham");
    let cham = home.join("cham");
    let code = cham.join("code");
    fs::create_dir_all(&code).unwrap();
    fs::write(
        static_config_file_path(code.to_str().unwrap()),
        r#"{"aws_name":"NvMainnet3"}"#,
    )
    .unwrap();

    let cfg = StaticConfig::load_from_home(home.to_str().unwrap());
    assert_eq!(cfg.cham_dir, cham.to_str().unwrap());
    assert_eq!(cfg.code_dir, code_dir_for_cham_dir(&cfg.cham_dir));
    assert_eq!(cfg.aws_name, AwsName::NvMainnet3);
    let _ = fs::remove_dir_all(&home);

    // Case 2: neither /cham nor /hl exists -> creates /hl; missing static_config -> NvTestnet (33).
    let home2 = fresh_temp_dir("hl-create");
    let cfg2 = StaticConfig::load_from_home(home2.to_str().unwrap());
    assert_eq!(cfg2.cham_dir, format!("{}/hl", home2.to_str().unwrap()));
    assert!(PathBuf::from(&cfg2.cham_dir).is_dir());
    assert_eq!(cfg2.aws_name, AwsName::NvTestnet);

    // Case 3: malformed static_config -> NvTestnet (33).
    fs::create_dir_all(&cfg2.code_dir).unwrap();
    fs::write(static_config_file_path(&cfg2.code_dir), "{bad json").unwrap();
    assert_eq!(read_aws_name(&cfg2.code_dir, &cfg2.cham_dir), AwsName::NvTestnet);

    // Case 4: valid JSON missing aws_name -> reads {cham_dir}/aws_name with Unicode trim.
    fs::write(static_config_file_path(&cfg2.code_dir), "{}").unwrap();
    fs::write(aws_name_path_for_cham_dir(&cfg2.cham_dir), "  \u{00a0}SoloSandbox\n").unwrap();
    assert_eq!(
        read_aws_name(&cfg2.code_dir, &cfg2.cham_dir),
        AwsName::SoloSandbox
    );

    // Case 5: resolve_cham_dir returns existing /hl without error.
    assert_eq!(resolve_cham_dir(home2.to_str().unwrap()), cfg2.cham_dir);
    let _ = fs::remove_dir_all(&home2);
}

#[test]
#[should_panic]
fn missing_aws_name_field_panics_when_fallback_file_absent() {
    let home = fresh_temp_dir("missing-fallback");
    let hl = home.join("hl");
    let code = hl.join("code");
    fs::create_dir_all(&code).unwrap();
    fs::write(static_config_file_path(code.to_str().unwrap()), "{}").unwrap();
    // 0x1777a3b -> 0x1773fd0 panics (does NOT return NvTestnet) when /aws_name is absent.
    let _ = read_aws_name(code.to_str().unwrap(), hl.to_str().unwrap());
}

#[test]
fn joined_chain_and_spot_mark_codecs() {
    for c in ChainName::ALL {
        assert_eq!(ChainDisplay(c).to_string(), c.name());
        assert_eq!(ChainName::from_name(c.name()), Some(c));
    }
    for k in SpotMarkKind::ALL {
        assert_eq!(SpotMarkKind::from_name(k.name()), Some(k));
    }
}

#[test]
fn aws_name_213_non_local_chain_guard_allows_non_local_and_panics_on_local() {
    for chain in [ChainName::Sandbox, ChainName::Testnet, ChainName::Mainnet] {
        AwsName::assert_non_local_chain(chain);
    }
    let panic_res = std::panic::catch_unwind(|| {
        AwsName::assert_non_local_chain(ChainName::Local);
    });
    assert!(panic_res.is_err());
}

#[test]
fn missing_aws_name_fallback_invalid_spelling_panics() {
    let home = fresh_temp_dir("invalid-fallback");
    let hl = home.join("hl");
    let code = hl.join("code");
    fs::create_dir_all(&code).unwrap();
    fs::write(static_config_file_path(code.to_str().unwrap()), "{}").unwrap();
    fs::write(aws_name_path_for_cham_dir(hl.to_str().unwrap()), "NotARealAwsName\n").unwrap();
    // Matches 0x1774092 (aws_name.rs:295:68 parse unwrap panic).
    let res = std::panic::catch_unwind(|| read_aws_name(code.to_str().unwrap(), hl.to_str().unwrap()));
    assert!(res.is_err());
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn resolve_cham_dir_panics_when_hl_blocked_by_regular_file() {
    let home = fresh_temp_dir("hl-blocked");
    let hl_file = home.join("hl");
    fs::write(&hl_file, b"not a directory").unwrap();
    // Matches 0x1778270 (static_config.rs:61:17 "could not create {hl}: {err}").
    let res = std::panic::catch_unwind(|| resolve_cham_dir(home.to_str().unwrap()));
    assert!(res.is_err());
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn lazy_lock_concurrency_and_poisoning_and_home_dir_resolution() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, LazyLock};

    // 1. Concurrent LazyLock initialization executes exactly once across 8 threads.
    let home = fresh_temp_dir("lazy-conc");
    let cham = home.join("cham");
    let code = cham.join("code");
    fs::create_dir_all(&code).unwrap();
    fs::write(
        static_config_file_path(code.to_str().unwrap()),
        r#"{"aws_name":"EaTx"}"#,
    )
    .unwrap();

    let init_calls = Arc::new(AtomicUsize::new(0));
    let home_str = home.to_str().unwrap().to_owned();
    let calls_ref = Arc::clone(&init_calls);
    let cell = Arc::new(LazyLock::new(move || {
        calls_ref.fetch_add(1, Ordering::SeqCst);
        StaticConfig::load_from_home(home_str.clone())
    }));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = Arc::clone(&cell);
        handles.push(std::thread::spawn(move || c.aws_name));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), AwsName::EaTx);
    }
    assert_eq!(init_calls.load(Ordering::SeqCst), 1);
    let _ = fs::remove_dir_all(&home);

    // 2. Poisoned LazyLock panics on subsequent access (matching 0x1774bf0/0x1774c80).
    let poisoned: LazyLock<StaticConfig> = LazyLock::new(|| panic!("simulated init failure"));
    assert!(std::panic::catch_unwind(|| &*poisoned).is_err());
    assert!(std::panic::catch_unwind(|| &*poisoned).is_err());

    // 3. `home_dir()` resolves non-empty path on Linux (using std::env::home_dir -> HOME / getpwuid_r).
    let resolved = global_constants::home_dir();
    assert!(!resolved.is_empty());
}
