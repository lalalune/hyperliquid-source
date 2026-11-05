use node115_asset_metadata_encoder::{
    AssetMetadata, GrowthMode, MarginMode, OutsideTimestampProfile, Timestamp, encode,
};

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "invalid frozen hexadecimal data");
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn frozen_whole_records() {
    let corpus = include_str!(
        "../../../research/work-items/RE-005-asset-metadata-encoder-115/frozen-cases.tsv"
    );
    let mut count = 0;
    for line in corpus.lines() {
        if line.starts_with('#') {
            continue;
        }
        let c: Vec<_> = line.split('\t').collect();
        assert_eq!(c.len(), 14, "frozen input schema changed");
        let name = String::from_utf8(unhex(c[2])).unwrap();
        let value = AssetMetadata {
            sz_decimals: c[1].parse().unwrap(),
            name: &name,
            max_leverage: c[3].parse().unwrap(),
            margin_table_id: c[4].parse().unwrap(),
            only_isolated: c[5] == "1",
            is_delisted: c[6] == "1",
            margin_mode: match c[7] {
                "0" => MarginMode::Normal,
                "1" => MarginMode::NoCross,
                "2" => MarginMode::StrictIsolated,
                _ => panic!("invalid frozen mode"),
            },
            growth_mode: match c[8] {
                "0" => GrowthMode::Enabled,
                "1" => GrowthMode::Disabled,
                "2" => GrowthMode::Blocked,
                _ => panic!("invalid frozen mode"),
            },
            last_fee_scale_change_time: (c[9] != "-").then(|| Timestamp {
                packed_date: c[9].parse().unwrap(),
                seconds: c[10].parse().unwrap(),
                nanos: c[11].parse().unwrap(),
            }),
            deployer_fee_scale: (c[12] != "-")
                .then(|| f64::from_bits(u64::from_str_radix(c[12], 16).unwrap())),
        };
        assert_eq!(encode(&value).unwrap().as_bytes(), unhex(c[13]), "{}", c[0]);
        count += 1;
    }
    assert_eq!(count, 223, "whole-record frozen denominator changed");
}

#[test]
fn local_timestamp_validation_is_not_a_native_error_claim() {
    let base = AssetMetadata {
        sz_decimals: 0,
        name: "",
        max_leverage: 0,
        margin_table_id: 0,
        only_isolated: false,
        is_delisted: false,
        margin_mode: MarginMode::Normal,
        growth_mode: GrowthMode::Disabled,
        last_fee_scale_change_time: None,
        deployer_fee_scale: None,
    };
    for t in [
        Timestamp {
            packed_date: 0,
            seconds: 0,
            nanos: 0,
        },
        Timestamp {
            packed_date: 1 << 13 | 16,
            seconds: 86400,
            nanos: 0,
        },
        Timestamp {
            packed_date: 1 << 13 | 16,
            seconds: 0,
            nanos: 2_000_000_000,
        },
        Timestamp {
            packed_date: 1 << 13 | 733 << 3,
            seconds: 0,
            nanos: 0,
        },
    ] {
        let value = AssetMetadata {
            last_fee_scale_change_time: Some(t),
            ..base
        };
        assert_eq!(encode(&value), Err(OutsideTimestampProfile));
    }
}
