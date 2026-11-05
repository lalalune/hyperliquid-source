use node115_info_request_value::{
    Address, FileSnapshotRequest, InfoRequest, RequestValue, to_value,
};
use std::fmt::Write;

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn quoted(value: &str) -> String {
    let mut s = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\u{8}' => s.push_str("\\b"),
            '\t' => s.push_str("\\t"),
            '\n' => s.push_str("\\n"),
            '\u{c}' => s.push_str("\\f"),
            '\r' => s.push_str("\\r"),
            c if (c as u32) < 32 => write!(s, "\\u{:04x}", c as u32).unwrap(),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}
/// Test-only canonical rendering; this is not the captured byte serializer.
fn canonical(value: &RequestValue) -> String {
    match value {
        RequestValue::Null => "null".into(),
        RequestValue::Bool(v) => v.to_string(),
        RequestValue::Unsigned(v) => v.to_string(),
        RequestValue::String(v) => quoted(v),
        RequestValue::Object(v) => {
            let mut fields: Vec<_> = v.iter().collect();
            fields.sort_unstable_by_key(|(key, _)| *key);
            let rows: Vec<_> = fields
                .iter()
                .map(|(k, v)| format!("{}:{}", quoted(k), canonical(v)))
                .collect();
            format!("{{{}}}", rows.join(","))
        }
    }
}
fn keys(value: &RequestValue) -> Vec<&'static str> {
    let RequestValue::Object(fields) = value else {
        panic!("expected object")
    };
    fields.iter().map(|(key, _)| *key).collect()
}

struct Input<'a> {
    text: &'a str,
    out_path: &'a str,
    address: Address,
    builder: Address,
    number64: u64,
    number32: u32,
    flag: bool,
    optional: Option<Address>,
    snapshot: FileSnapshotRequest<'a>,
}

fn request<'a>(index: usize, i: &Input<'a>) -> InfoRequest<'a> {
    match index {
        0 => InfoRequest::FileSnapshot {
            request: i.snapshot.clone(),
            out_path: i.out_path,
            include_height_in_output: i.flag,
        },
        1 => InfoRequest::WebData2 { user: i.optional },
        2 => InfoRequest::WebData3 { user: i.address },
        3 => InfoRequest::Meta { dex: i.text },
        4 => InfoRequest::SpotMeta {
            include_debug_details: i.flag,
        },
        5 => InfoRequest::OutcomeMeta,
        6 => InfoRequest::OutcomeDeployerLimits { venue: i.text },
        7 => InfoRequest::ClearinghouseState {
            user: i.address,
            dex: i.text,
        },
        8 => InfoRequest::SpotClearinghouseState {
            user: i.address,
            ignore_portfolio_margin: i.flag,
        },
        9 => InfoRequest::OpenOrders {
            user: i.address,
            dex: i.text,
        },
        10 => InfoRequest::ExchangeStatus,
        11 => InfoRequest::FrontendOpenOrders {
            user: i.address,
            dex: i.text,
        },
        12 => InfoRequest::ActiveAssetData {
            user: i.address,
            coin: i.text,
        },
        13 => InfoRequest::MaxMarketOrderNtls,
        14 => InfoRequest::VaultSummaries { leader: i.optional },
        15 => InfoRequest::UserVaultEquities { user: i.address },
        16 => InfoRequest::LeadingVaults { user: i.address },
        17 => InfoRequest::ExtraAgents { user: i.address },
        18 => InfoRequest::SubAccounts {
            user: i.address,
            dex: i.text,
        },
        19 => InfoRequest::SubAccounts2 { user: i.address },
        20 => InfoRequest::UserFees { user: i.address },
        21 => InfoRequest::UserRateLimit { user: i.address },
        22 => InfoRequest::SpotDeployState { user: i.address },
        23 => InfoRequest::SpotPairDeployAuctionStatus,
        24 => InfoRequest::PerpDeployAuctionStatus,
        25 => InfoRequest::Votes { user: i.address },
        26 => InfoRequest::Delegations { user: i.address },
        27 => InfoRequest::DelegatorSummary { user: i.address },
        28 => InfoRequest::MaxBuilderFee {
            user: i.address,
            builder: i.builder,
        },
        29 => InfoRequest::UserToMultiSigSigners { user: i.address },
        30 => InfoRequest::UserRole { user: i.address },
        31 => InfoRequest::PerpsAtOpenInterestCap { dex: i.text },
        32 => InfoRequest::PerpDexLimits { dex: i.text },
        33 => InfoRequest::ValidatorL1Votes,
        34 => InfoRequest::MarginTable {
            dex: i.text,
            id: i.number32,
        },
        35 => InfoRequest::PerpDexs,
        36 => InfoRequest::AllPerpMetas,
        37 => InfoRequest::UserDexAbstraction { user: i.address },
        38 => InfoRequest::PerpDexStatus { dex: i.text },
        39 => InfoRequest::BorrowLendUserState { user: i.address },
        40 => InfoRequest::BorrowLendReserveState { token: i.number64 },
        41 => InfoRequest::AllBorrowLendReserveStates,
        42 => InfoRequest::UserAbstraction { user: i.address },
        43 => InfoRequest::PerpAnnotation { coin: i.text },
        44 => InfoRequest::PerpCategories,
        45 => InfoRequest::PerpConciseAnnotations,
        46 => InfoRequest::TokenAnnotation { token: i.number64 },
        47 => InfoRequest::TokenConciseAnnotations,
        48 => InfoRequest::SettledOutcome {
            outcome: i.number64,
            only_use_db: i.flag,
        },
        49 => InfoRequest::SettledQuestion {
            question: i.number64,
            only_use_db: i.flag,
        },
        50 => InfoRequest::ApprovedBuilders { user: i.address },
        51 => InfoRequest::GossipPriorityAuctionStatus,
        52 => InfoRequest::OutcomeTemplates,
        53 => InfoRequest::Aqav2InterestHistory { token: i.number64 },
        54 => InfoRequest::UserStarState { user: i.address },
        _ => panic!("unknown frozen selector"),
    }
}

#[test]
fn frozen_whole_values() {
    let data =
        include_str!("../../../research/work-items/RE-005-info-request-value-115/frozen-cases.tsv");
    let mut count = 0;
    let mut variants = [0usize; 55];
    for line in data.lines() {
        if line.starts_with('#') {
            continue;
        }
        let c: Vec<_> = line.split('\t').collect();
        assert_eq!(c.len(), 18);
        let index: usize = c[1].parse().unwrap();
        let text = String::from_utf8(unhex(c[2])).unwrap();
        let out_path = String::from_utf8(unhex(c[3])).unwrap();
        let address: Address = unhex(c[4]).try_into().unwrap();
        let builder: Address = unhex(c[5]).try_into().unwrap();
        let snapshot = if c[10] == "0" {
            FileSnapshotRequest::ReferrerStates
        } else {
            FileSnapshotRequest::L4Snapshots {
                coin: (c[11] == "1").then_some(text.as_str()),
                include_users: c[12] == "1",
                include_trigger_orders: c[13] == "1",
                include_l4_details: c[14] == "1",
            }
        };
        let i = Input {
            text: &text,
            out_path: &out_path,
            address,
            builder,
            number64: c[6].parse().unwrap(),
            number32: c[7].parse().unwrap(),
            flag: c[8] == "1",
            optional: (c[9] == "1").then_some(address),
            snapshot,
        };
        let value = to_value(&request(index, &i));
        assert_eq!(canonical(&value).as_bytes(), unhex(c[15]), "{}", c[0]);
        assert_eq!(
            keys(&value),
            c[16].split(',').collect::<Vec<_>>(),
            "{} field order",
            c[0]
        );
        if index == 0 {
            let RequestValue::Object(fields) = &value else {
                unreachable!()
            };
            let nested = &fields.iter().find(|(key, _)| *key == "request").unwrap().1;
            assert_eq!(
                keys(nested),
                c[17].split(',').collect::<Vec<_>>(),
                "{} nested order",
                c[0]
            );
        }
        variants[index] += 1;
        count += 1;
    }
    assert_eq!(count, 190);
    assert!(
        variants.into_iter().all(|n| n >= 2),
        "every native branch must have default and changed values"
    );
}
