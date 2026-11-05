// Generated only from the pre-implementation frozen static cases.
use node115_context_encoder::{
    Context, Hardfork, Mode, OutsideTimestampProfile, Timestamp, encode, timestamp_text,
};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn boundary_0_sequence() {
    let ctx = Context {
        hardfork_height: 0,
        hardfork: Hardfork {
            version: 127,
            round: 128,
        },
        height: 255,
        tx_index: None,
        round: 65535,
        time: Timestamp {
            packed_date: 17,
            seconds: 0,
            nanos: 0,
        },
        prev_time: Timestamp {
            packed_date: 15565753,
            seconds: 86399,
            nanos: 999999999,
        },
        next_oid: 65536,
        next_lid: 4294967295,
        next_twap_id: 4294967296,
        system_nonce: 18446744073709551615,
        use_system_nonce: false,
        mac: 256,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "0000-01-01T00:00:00");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "1900-02-28T23:59:59.999999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9d00927fcc80ccffc0cdffffb3303030302d30312d30315430303a30303a3030bd313930302d30322d32385432333a35393a35392e393939393939393939ce00010000ceffffffffcf0000000100000000cfffffffffffffffffc2cd0100"
        )
    );
}
#[test]
fn boundary_0_map() {
    let ctx = Context {
        hardfork_height: 0,
        hardfork: Hardfork {
            version: 127,
            round: 128,
        },
        height: 255,
        tx_index: None,
        round: 65535,
        time: Timestamp {
            packed_date: 17,
            seconds: 0,
            nanos: 0,
        },
        prev_time: Timestamp {
            packed_date: 15565753,
            seconds: 86399,
            nanos: 999999999,
        },
        next_oid: 65536,
        next_lid: 4294967295,
        next_twap_id: 4294967296,
        system_nonce: 18446744073709551615,
        use_system_nonce: false,
        mac: 256,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "0000-01-01T00:00:00");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "1900-02-28T23:59:59.999999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f68656967687400a868617264666f726b82a776657273696f6e7fa5726f756e64cc80a6686569676874ccffa874785f696e646578c0a5726f756e64cdffffa474696d65b3303030302d30312d30315430303a30303a3030a9707265765f74696d65bd313930302d30322d32385432333a35393a35392e393939393939393939a86e6578745f6f6964ce00010000a86e6578745f6c6964ceffffffffac6e6578745f747761705f6964cf0000000100000000ac73797374656d5f6e6f6e6365cfffffffffffffffffb07573655f73797374656d5f6e6f6e6365c2a36d6163cd0100"
        )
    );
}
#[test]
fn boundary_1_sequence() {
    let ctx = Context {
        hardfork_height: 127,
        hardfork: Hardfork {
            version: 128,
            round: 255,
        },
        height: 256,
        tx_index: Some(65535),
        round: 65536,
        time: Timestamp {
            packed_date: 14041,
            seconds: 86399,
            nanos: 1,
        },
        prev_time: Timestamp {
            packed_date: -2147477791,
            seconds: 0,
            nanos: 999999999,
        },
        next_oid: 4294967295,
        next_lid: 4294967296,
        next_twap_id: 18446744073709551615,
        system_nonce: 0,
        use_system_nonce: true,
        mac: 65535,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "0001-12-31T23:59:59.000000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "-262144-12-31T00:00:00.999999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9d7f92cc80ccffcd0100cdffffce00010000bd303030312d31322d33315432333a35393a35392e303030303030303031d9202d3236323134342d31322d33315430303a30303a30302e393939393939393939ceffffffffcf0000000100000000cfffffffffffffffff00c3cdffff"
        )
    );
}
#[test]
fn boundary_1_map() {
    let ctx = Context {
        hardfork_height: 127,
        hardfork: Hardfork {
            version: 128,
            round: 255,
        },
        height: 256,
        tx_index: Some(65535),
        round: 65536,
        time: Timestamp {
            packed_date: 14041,
            seconds: 86399,
            nanos: 1,
        },
        prev_time: Timestamp {
            packed_date: -2147477791,
            seconds: 0,
            nanos: 999999999,
        },
        next_oid: 4294967295,
        next_lid: 4294967296,
        next_twap_id: 18446744073709551615,
        system_nonce: 0,
        use_system_nonce: true,
        mac: 65535,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "0001-12-31T23:59:59.000000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "-262144-12-31T00:00:00.999999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f6865696768747fa868617264666f726b82a776657273696f6ecc80a5726f756e64ccffa6686569676874cd0100a874785f696e646578cdffffa5726f756e64ce00010000a474696d65bd303030312d31322d33315432333a35393a35392e303030303030303031a9707265765f74696d65d9202d3236323134342d31322d33315430303a30303a30302e393939393939393939a86e6578745f6f6964ceffffffffa86e6578745f6c6964cf0000000100000000ac6e6578745f747761705f6964cfffffffffffffffffac73797374656d5f6e6f6e636500b07573655f73797374656d5f6e6f6e6365c3a36d6163cdffff"
        )
    );
}
#[test]
fn boundary_2_sequence() {
    let ctx = Context {
        hardfork_height: 128,
        hardfork: Hardfork {
            version: 255,
            round: 256,
        },
        height: 65535,
        tx_index: None,
        round: 4294967295,
        time: Timestamp {
            packed_date: -8167,
            seconds: 59,
            nanos: 1000000000,
        },
        prev_time: Timestamp {
            packed_date: 2147481305,
            seconds: 86399,
            nanos: 123456000,
        },
        next_oid: 4294967296,
        next_lid: 18446744073709551615,
        next_twap_id: 0,
        system_nonce: 127,
        use_system_nonce: false,
        mac: 65536,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "-0001-01-01T00:00:60");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "+262143-12-31T23:59:59.123456"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcc8092ccffcd0100cdffffc0ceffffffffb42d303030312d30312d30315430303a30303a3630bd2b3236323134332d31322d33315432333a35393a35392e313233343536cf0000000100000000cfffffffffffffffff007fc2ce00010000"
        )
    );
}
#[test]
fn boundary_2_map() {
    let ctx = Context {
        hardfork_height: 128,
        hardfork: Hardfork {
            version: 255,
            round: 256,
        },
        height: 65535,
        tx_index: None,
        round: 4294967295,
        time: Timestamp {
            packed_date: -8167,
            seconds: 59,
            nanos: 1000000000,
        },
        prev_time: Timestamp {
            packed_date: 2147481305,
            seconds: 86399,
            nanos: 123456000,
        },
        next_oid: 4294967296,
        next_lid: 18446744073709551615,
        next_twap_id: 0,
        system_nonce: 127,
        use_system_nonce: false,
        mac: 65536,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "-0001-01-01T00:00:60");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "+262143-12-31T23:59:59.123456"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cc80a868617264666f726b82a776657273696f6eccffa5726f756e64cd0100a6686569676874cdffffa874785f696e646578c0a5726f756e64ceffffffffa474696d65b42d303030312d30312d30315430303a30303a3630a9707265765f74696d65bd2b3236323134332d31322d33315432333a35393a35392e313233343536a86e6578745f6f6964cf0000000100000000a86e6578745f6c6964cfffffffffffffffffac6e6578745f747761705f696400ac73797374656d5f6e6f6e63657fb07573655f73797374656d5f6e6f6e6365c2a36d6163ce00010000"
        )
    );
}
#[test]
fn boundary_3_sequence() {
    let ctx = Context {
        hardfork_height: 255,
        hardfork: Hardfork {
            version: 256,
            round: 65535,
        },
        height: 65536,
        tx_index: Some(4294967295),
        round: 4294967296,
        time: Timestamp {
            packed_date: 81917657,
            seconds: 3600,
            nanos: 1000,
        },
        prev_time: Timestamp {
            packed_date: 16586465,
            seconds: 60,
            nanos: 999000000,
        },
        next_oid: 18446744073709551615,
        next_lid: 0,
        next_twap_id: 127,
        system_nonce: 128,
        use_system_nonce: true,
        mac: 4294967295,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "9999-12-31T01:00:00.000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-12-31T00:01:00.999"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dccff92cd0100cdffffce00010000ceffffffffcf0000000100000000ba393939392d31322d33315430313a30303a30302e303030303031b7323032342d31322d33315430303a30313a30302e393939cfffffffffffffffff007fcc80c3ceffffffff"
        )
    );
}
#[test]
fn boundary_3_map() {
    let ctx = Context {
        hardfork_height: 255,
        hardfork: Hardfork {
            version: 256,
            round: 65535,
        },
        height: 65536,
        tx_index: Some(4294967295),
        round: 4294967296,
        time: Timestamp {
            packed_date: 81917657,
            seconds: 3600,
            nanos: 1000,
        },
        prev_time: Timestamp {
            packed_date: 16586465,
            seconds: 60,
            nanos: 999000000,
        },
        next_oid: 18446744073709551615,
        next_lid: 0,
        next_twap_id: 127,
        system_nonce: 128,
        use_system_nonce: true,
        mac: 4294967295,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "9999-12-31T01:00:00.000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-12-31T00:01:00.999"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874ccffa868617264666f726b82a776657273696f6ecd0100a5726f756e64cdffffa6686569676874ce00010000a874785f696e646578ceffffffffa5726f756e64cf0000000100000000a474696d65ba393939392d31322d33315430313a30303a30302e303030303031a9707265765f74696d65b7323032342d31322d33315430303a30313a30302e393939a86e6578745f6f6964cfffffffffffffffffa86e6578745f6c696400ac6e6578745f747761705f69647fac73797374656d5f6e6f6e6365cc80b07573655f73797374656d5f6e6f6e6365c3a36d6163ceffffffff"
        )
    );
}
#[test]
fn boundary_4_sequence() {
    let ctx = Context {
        hardfork_height: 256,
        hardfork: Hardfork {
            version: 65535,
            round: 65536,
        },
        height: 4294967295,
        tx_index: None,
        round: 18446744073709551615,
        time: Timestamp {
            packed_date: 81925857,
            seconds: 86399,
            nanos: 1000000,
        },
        prev_time: Timestamp {
            packed_date: 16578265,
            seconds: 3599,
            nanos: 1000000001,
        },
        next_oid: 0,
        next_lid: 127,
        next_twap_id: 128,
        system_nonce: 255,
        use_system_nonce: false,
        mac: 4294967296,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "+10000-12-31T23:59:59.001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2023-12-31T00:59:60.000000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcd010092cdffffce00010000ceffffffffc0cfffffffffffffffffb92b31303030302d31322d33315432333a35393a35392e303031bd323032332d31322d33315430303a35393a36302e303030303030303031007fcc80ccffc2cf0000000100000000"
        )
    );
}
#[test]
fn boundary_4_map() {
    let ctx = Context {
        hardfork_height: 256,
        hardfork: Hardfork {
            version: 65535,
            round: 65536,
        },
        height: 4294967295,
        tx_index: None,
        round: 18446744073709551615,
        time: Timestamp {
            packed_date: 81925857,
            seconds: 86399,
            nanos: 1000000,
        },
        prev_time: Timestamp {
            packed_date: 16578265,
            seconds: 3599,
            nanos: 1000000001,
        },
        next_oid: 0,
        next_lid: 127,
        next_twap_id: 128,
        system_nonce: 255,
        use_system_nonce: false,
        mac: 4294967296,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "+10000-12-31T23:59:59.001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2023-12-31T00:59:60.000000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cd0100a868617264666f726b82a776657273696f6ecdffffa5726f756e64ce00010000a6686569676874ceffffffffa874785f696e646578c0a5726f756e64cfffffffffffffffffa474696d65b92b31303030302d31322d33315432333a35393a35392e303031a9707265765f74696d65bd323032332d31322d33315430303a35393a36302e303030303030303031a86e6578745f6f696400a86e6578745f6c69647fac6e6578745f747761705f6964cc80ac73797374656d5f6e6f6e6365ccffb07573655f73797374656d5f6e6f6e6365c2a36d6163cf0000000100000000"
        )
    );
}
#[test]
fn boundary_5_sequence() {
    let ctx = Context {
        hardfork_height: 65535,
        hardfork: Hardfork {
            version: 65536,
            round: 4294967295,
        },
        height: 4294967296,
        tx_index: Some(18446744073709551615),
        round: 0,
        time: Timestamp {
            packed_date: -81919039,
            seconds: 45296,
            nanos: 123456789,
        },
        prev_time: Timestamp {
            packed_date: 16581569,
            seconds: 59,
            nanos: 1001000000,
        },
        next_oid: 127,
        next_lid: 128,
        next_twap_id: 255,
        system_nonce: 256,
        use_system_nonce: true,
        mac: 18446744073709551615,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "-10000-02-29T12:34:56.123456789"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-02-29T00:00:60.001"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcdffff92ce00010000ceffffffffcf0000000100000000cfffffffffffffffff00bf2d31303030302d30322d32395431323a33343a35362e313233343536373839b7323032342d30322d32395430303a30303a36302e3030317fcc80ccffcd0100c3cfffffffffffffffff"
        )
    );
}
#[test]
fn boundary_5_map() {
    let ctx = Context {
        hardfork_height: 65535,
        hardfork: Hardfork {
            version: 65536,
            round: 4294967295,
        },
        height: 4294967296,
        tx_index: Some(18446744073709551615),
        round: 0,
        time: Timestamp {
            packed_date: -81919039,
            seconds: 45296,
            nanos: 123456789,
        },
        prev_time: Timestamp {
            packed_date: 16581569,
            seconds: 59,
            nanos: 1001000000,
        },
        next_oid: 127,
        next_lid: 128,
        next_twap_id: 255,
        system_nonce: 256,
        use_system_nonce: true,
        mac: 18446744073709551615,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "-10000-02-29T12:34:56.123456789"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-02-29T00:00:60.001"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cdffffa868617264666f726b82a776657273696f6ece00010000a5726f756e64ceffffffffa6686569676874cf0000000100000000a874785f696e646578cfffffffffffffffffa5726f756e6400a474696d65bf2d31303030302d30322d32395431323a33343a35362e313233343536373839a9707265765f74696d65b7323032342d30322d32395430303a30303a36302e303031a86e6578745f6f69647fa86e6578745f6c6964cc80ac6e6578745f747761705f6964ccffac73797374656d5f6e6f6e6365cd0100b07573655f73797374656d5f6e6f6e6365c3a36d6163cfffffffffffffffff"
        )
    );
}
#[test]
fn boundary_6_sequence() {
    let ctx = Context {
        hardfork_height: 65536,
        hardfork: Hardfork {
            version: 4294967295,
            round: 4294967296,
        },
        height: 18446744073709551615,
        tx_index: None,
        round: 127,
        time: Timestamp {
            packed_date: 16384961,
            seconds: 59,
            nanos: 1999999999,
        },
        prev_time: Timestamp {
            packed_date: 16581585,
            seconds: 59,
            nanos: 1000001000,
        },
        next_oid: 128,
        next_lid: 255,
        next_twap_id: 256,
        system_nonce: 65535,
        use_system_nonce: false,
        mac: 0,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2000-02-29T00:00:60.999999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-03-01T00:00:60.000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dce0001000092ceffffffffcf0000000100000000cfffffffffffffffffc07fbd323030302d30322d32395430303a30303a36302e393939393939393939ba323032342d30332d30315430303a30303a36302e303030303031cc80ccffcd0100cdffffc200"
        )
    );
}
#[test]
fn boundary_6_map() {
    let ctx = Context {
        hardfork_height: 65536,
        hardfork: Hardfork {
            version: 4294967295,
            round: 4294967296,
        },
        height: 18446744073709551615,
        tx_index: None,
        round: 127,
        time: Timestamp {
            packed_date: 16384961,
            seconds: 59,
            nanos: 1999999999,
        },
        prev_time: Timestamp {
            packed_date: 16581585,
            seconds: 59,
            nanos: 1000001000,
        },
        next_oid: 128,
        next_lid: 255,
        next_twap_id: 256,
        system_nonce: 65535,
        use_system_nonce: false,
        mac: 0,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2000-02-29T00:00:60.999999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-03-01T00:00:60.000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874ce00010000a868617264666f726b82a776657273696f6eceffffffffa5726f756e64cf0000000100000000a6686569676874cfffffffffffffffffa874785f696e646578c0a5726f756e647fa474696d65bd323030302d30322d32395430303a30303a36302e393939393939393939a9707265765f74696d65ba323032342d30332d30315430303a30303a36302e303030303031a86e6578745f6f6964cc80a86e6578745f6c6964ccffac6e6578745f747761705f6964cd0100ac73797374656d5f6e6f6e6365cdffffb07573655f73797374656d5f6e6f6e6365c2a36d616300"
        )
    );
}
#[test]
fn boundary_7_sequence() {
    let ctx = Context {
        hardfork_height: 4294967295,
        hardfork: Hardfork {
            version: 4294967296,
            round: 18446744073709551615,
        },
        height: 0,
        tx_index: Some(127),
        round: 128,
        time: Timestamp {
            packed_date: 15565753,
            seconds: 86399,
            nanos: 999999999,
        },
        prev_time: Timestamp {
            packed_date: 16580625,
            seconds: 0,
            nanos: 999999000,
        },
        next_oid: 255,
        next_lid: 256,
        next_twap_id: 65535,
        system_nonce: 65536,
        use_system_nonce: true,
        mac: 127,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "1900-02-28T23:59:59.999999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-01-01T00:00:00.999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dceffffffff92cf0000000100000000cfffffffffffffffff007fcc80bd313930302d30322d32385432333a35393a35392e393939393939393939ba323032342d30312d30315430303a30303a30302e393939393939ccffcd0100cdffffce00010000c37f"
        )
    );
}
#[test]
fn boundary_7_map() {
    let ctx = Context {
        hardfork_height: 4294967295,
        hardfork: Hardfork {
            version: 4294967296,
            round: 18446744073709551615,
        },
        height: 0,
        tx_index: Some(127),
        round: 128,
        time: Timestamp {
            packed_date: 15565753,
            seconds: 86399,
            nanos: 999999999,
        },
        prev_time: Timestamp {
            packed_date: 16580625,
            seconds: 0,
            nanos: 999999000,
        },
        next_oid: 255,
        next_lid: 256,
        next_twap_id: 65535,
        system_nonce: 65536,
        use_system_nonce: true,
        mac: 127,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "1900-02-28T23:59:59.999999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-01-01T00:00:00.999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874ceffffffffa868617264666f726b82a776657273696f6ecf0000000100000000a5726f756e64cfffffffffffffffffa668656967687400a874785f696e6465787fa5726f756e64cc80a474696d65bd313930302d30322d32385432333a35393a35392e393939393939393939a9707265765f74696d65ba323032342d30312d30315430303a30303a30302e393939393939a86e6578745f6f6964ccffa86e6578745f6c6964cd0100ac6e6578745f747761705f6964cdffffac73797374656d5f6e6f6e6365ce00010000b07573655f73797374656d5f6e6f6e6365c3a36d61637f"
        )
    );
}
#[test]
fn boundary_8_sequence() {
    let ctx = Context {
        hardfork_height: 4294967296,
        hardfork: Hardfork {
            version: 18446744073709551615,
            round: 0,
        },
        height: 127,
        tx_index: None,
        round: 255,
        time: Timestamp {
            packed_date: -2147477791,
            seconds: 0,
            nanos: 999999999,
        },
        prev_time: Timestamp {
            packed_date: 16580625,
            seconds: 86399,
            nanos: 1999999000,
        },
        next_oid: 256,
        next_lid: 65535,
        next_twap_id: 65536,
        system_nonce: 4294967295,
        use_system_nonce: false,
        mac: 128,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "-262144-12-31T00:00:00.999999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-01-01T23:59:60.999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcf000000010000000092cfffffffffffffffff007fc0ccffd9202d3236323134342d31322d33315430303a30303a30302e393939393939393939ba323032342d30312d30315432333a35393a36302e393939393939cd0100cdffffce00010000ceffffffffc2cc80"
        )
    );
}
#[test]
fn boundary_8_map() {
    let ctx = Context {
        hardfork_height: 4294967296,
        hardfork: Hardfork {
            version: 18446744073709551615,
            round: 0,
        },
        height: 127,
        tx_index: None,
        round: 255,
        time: Timestamp {
            packed_date: -2147477791,
            seconds: 0,
            nanos: 999999999,
        },
        prev_time: Timestamp {
            packed_date: 16580625,
            seconds: 86399,
            nanos: 1999999000,
        },
        next_oid: 256,
        next_lid: 65535,
        next_twap_id: 65536,
        system_nonce: 4294967295,
        use_system_nonce: false,
        mac: 128,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "-262144-12-31T00:00:00.999999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2024-01-01T23:59:60.999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cf0000000100000000a868617264666f726b82a776657273696f6ecfffffffffffffffffa5726f756e6400a66865696768747fa874785f696e646578c0a5726f756e64ccffa474696d65d9202d3236323134342d31322d33315430303a30303a30302e393939393939393939a9707265765f74696d65ba323032342d30312d30315432333a35393a36302e393939393939a86e6578745f6f6964cd0100a86e6578745f6c6964cdffffac6e6578745f747761705f6964ce00010000ac73797374656d5f6e6f6e6365ceffffffffb07573655f73797374656d5f6e6f6e6365c2a36d6163cc80"
        )
    );
}
#[test]
fn boundary_9_sequence() {
    let ctx = Context {
        hardfork_height: 18446744073709551615,
        hardfork: Hardfork {
            version: 0,
            round: 127,
        },
        height: 128,
        tx_index: Some(255),
        round: 256,
        time: Timestamp {
            packed_date: 2147481305,
            seconds: 86399,
            nanos: 123456000,
        },
        prev_time: Timestamp {
            packed_date: 17,
            seconds: 0,
            nanos: 0,
        },
        next_oid: 65535,
        next_lid: 65536,
        next_twap_id: 4294967295,
        system_nonce: 4294967296,
        use_system_nonce: true,
        mac: 255,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "+262143-12-31T23:59:59.123456"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "0000-01-01T00:00:00"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcfffffffffffffffff92007fcc80ccffcd0100bd2b3236323134332d31322d33315432333a35393a35392e313233343536b3303030302d30312d30315430303a30303a3030cdffffce00010000ceffffffffcf0000000100000000c3ccff"
        )
    );
}
#[test]
fn boundary_9_map() {
    let ctx = Context {
        hardfork_height: 18446744073709551615,
        hardfork: Hardfork {
            version: 0,
            round: 127,
        },
        height: 128,
        tx_index: Some(255),
        round: 256,
        time: Timestamp {
            packed_date: 2147481305,
            seconds: 86399,
            nanos: 123456000,
        },
        prev_time: Timestamp {
            packed_date: 17,
            seconds: 0,
            nanos: 0,
        },
        next_oid: 65535,
        next_lid: 65536,
        next_twap_id: 4294967295,
        system_nonce: 4294967296,
        use_system_nonce: true,
        mac: 255,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "+262143-12-31T23:59:59.123456"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "0000-01-01T00:00:00"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cfffffffffffffffffa868617264666f726b82a776657273696f6e00a5726f756e647fa6686569676874cc80a874785f696e646578ccffa5726f756e64cd0100a474696d65bd2b3236323134332d31322d33315432333a35393a35392e313233343536a9707265765f74696d65b3303030302d30312d30315430303a30303a3030a86e6578745f6f6964cdffffa86e6578745f6c6964ce00010000ac6e6578745f747761705f6964ceffffffffac73797374656d5f6e6f6e6365cf0000000100000000b07573655f73797374656d5f6e6f6e6365c3a36d6163ccff"
        )
    );
}
#[test]
fn boundary_10_sequence() {
    let ctx = Context {
        hardfork_height: 0,
        hardfork: Hardfork {
            version: 127,
            round: 128,
        },
        height: 255,
        tx_index: None,
        round: 65535,
        time: Timestamp {
            packed_date: 16586465,
            seconds: 60,
            nanos: 999000000,
        },
        prev_time: Timestamp {
            packed_date: 14041,
            seconds: 86399,
            nanos: 1,
        },
        next_oid: 65536,
        next_lid: 4294967295,
        next_twap_id: 4294967296,
        system_nonce: 18446744073709551615,
        use_system_nonce: false,
        mac: 256,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "2024-12-31T00:01:00.999");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "0001-12-31T23:59:59.000000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9d00927fcc80ccffc0cdffffb7323032342d31322d33315430303a30313a30302e393939bd303030312d31322d33315432333a35393a35392e303030303030303031ce00010000ceffffffffcf0000000100000000cfffffffffffffffffc2cd0100"
        )
    );
}
#[test]
fn boundary_10_map() {
    let ctx = Context {
        hardfork_height: 0,
        hardfork: Hardfork {
            version: 127,
            round: 128,
        },
        height: 255,
        tx_index: None,
        round: 65535,
        time: Timestamp {
            packed_date: 16586465,
            seconds: 60,
            nanos: 999000000,
        },
        prev_time: Timestamp {
            packed_date: 14041,
            seconds: 86399,
            nanos: 1,
        },
        next_oid: 65536,
        next_lid: 4294967295,
        next_twap_id: 4294967296,
        system_nonce: 18446744073709551615,
        use_system_nonce: false,
        mac: 256,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "2024-12-31T00:01:00.999");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "0001-12-31T23:59:59.000000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f68656967687400a868617264666f726b82a776657273696f6e7fa5726f756e64cc80a6686569676874ccffa874785f696e646578c0a5726f756e64cdffffa474696d65b7323032342d31322d33315430303a30313a30302e393939a9707265765f74696d65bd303030312d31322d33315432333a35393a35392e303030303030303031a86e6578745f6f6964ce00010000a86e6578745f6c6964ceffffffffac6e6578745f747761705f6964cf0000000100000000ac73797374656d5f6e6f6e6365cfffffffffffffffffb07573655f73797374656d5f6e6f6e6365c2a36d6163cd0100"
        )
    );
}
#[test]
fn boundary_11_sequence() {
    let ctx = Context {
        hardfork_height: 127,
        hardfork: Hardfork {
            version: 128,
            round: 255,
        },
        height: 256,
        tx_index: Some(65535),
        round: 65536,
        time: Timestamp {
            packed_date: 16578265,
            seconds: 3599,
            nanos: 1000000001,
        },
        prev_time: Timestamp {
            packed_date: -8167,
            seconds: 59,
            nanos: 1000000000,
        },
        next_oid: 4294967295,
        next_lid: 4294967296,
        next_twap_id: 18446744073709551615,
        system_nonce: 0,
        use_system_nonce: true,
        mac: 65535,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2023-12-31T00:59:60.000000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "-0001-01-01T00:00:60"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9d7f92cc80ccffcd0100cdffffce00010000bd323032332d31322d33315430303a35393a36302e303030303030303031b42d303030312d30312d30315430303a30303a3630ceffffffffcf0000000100000000cfffffffffffffffff00c3cdffff"
        )
    );
}
#[test]
fn boundary_11_map() {
    let ctx = Context {
        hardfork_height: 127,
        hardfork: Hardfork {
            version: 128,
            round: 255,
        },
        height: 256,
        tx_index: Some(65535),
        round: 65536,
        time: Timestamp {
            packed_date: 16578265,
            seconds: 3599,
            nanos: 1000000001,
        },
        prev_time: Timestamp {
            packed_date: -8167,
            seconds: 59,
            nanos: 1000000000,
        },
        next_oid: 4294967295,
        next_lid: 4294967296,
        next_twap_id: 18446744073709551615,
        system_nonce: 0,
        use_system_nonce: true,
        mac: 65535,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2023-12-31T00:59:60.000000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "-0001-01-01T00:00:60"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f6865696768747fa868617264666f726b82a776657273696f6ecc80a5726f756e64ccffa6686569676874cd0100a874785f696e646578cdffffa5726f756e64ce00010000a474696d65bd323032332d31322d33315430303a35393a36302e303030303030303031a9707265765f74696d65b42d303030312d30312d30315430303a30303a3630a86e6578745f6f6964ceffffffffa86e6578745f6c6964cf0000000100000000ac6e6578745f747761705f6964cfffffffffffffffffac73797374656d5f6e6f6e636500b07573655f73797374656d5f6e6f6e6365c3a36d6163cdffff"
        )
    );
}
#[test]
fn boundary_12_sequence() {
    let ctx = Context {
        hardfork_height: 128,
        hardfork: Hardfork {
            version: 255,
            round: 256,
        },
        height: 65535,
        tx_index: None,
        round: 4294967295,
        time: Timestamp {
            packed_date: 16581569,
            seconds: 59,
            nanos: 1001000000,
        },
        prev_time: Timestamp {
            packed_date: 81917657,
            seconds: 3600,
            nanos: 1000,
        },
        next_oid: 4294967296,
        next_lid: 18446744073709551615,
        next_twap_id: 0,
        system_nonce: 127,
        use_system_nonce: false,
        mac: 65536,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "2024-02-29T00:00:60.001");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "9999-12-31T01:00:00.000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcc8092ccffcd0100cdffffc0ceffffffffb7323032342d30322d32395430303a30303a36302e303031ba393939392d31322d33315430313a30303a30302e303030303031cf0000000100000000cfffffffffffffffff007fc2ce00010000"
        )
    );
}
#[test]
fn boundary_12_map() {
    let ctx = Context {
        hardfork_height: 128,
        hardfork: Hardfork {
            version: 255,
            round: 256,
        },
        height: 65535,
        tx_index: None,
        round: 4294967295,
        time: Timestamp {
            packed_date: 16581569,
            seconds: 59,
            nanos: 1001000000,
        },
        prev_time: Timestamp {
            packed_date: 81917657,
            seconds: 3600,
            nanos: 1000,
        },
        next_oid: 4294967296,
        next_lid: 18446744073709551615,
        next_twap_id: 0,
        system_nonce: 127,
        use_system_nonce: false,
        mac: 65536,
    };
    assert_eq!(timestamp_text(ctx.time).unwrap(), "2024-02-29T00:00:60.001");
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "9999-12-31T01:00:00.000001"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cc80a868617264666f726b82a776657273696f6eccffa5726f756e64cd0100a6686569676874cdffffa874785f696e646578c0a5726f756e64ceffffffffa474696d65b7323032342d30322d32395430303a30303a36302e303031a9707265765f74696d65ba393939392d31322d33315430313a30303a30302e303030303031a86e6578745f6f6964cf0000000100000000a86e6578745f6c6964cfffffffffffffffffac6e6578745f747761705f696400ac73797374656d5f6e6f6e63657fb07573655f73797374656d5f6e6f6e6365c2a36d6163ce00010000"
        )
    );
}
#[test]
fn boundary_13_sequence() {
    let ctx = Context {
        hardfork_height: 255,
        hardfork: Hardfork {
            version: 256,
            round: 65535,
        },
        height: 65536,
        tx_index: Some(4294967295),
        round: 4294967296,
        time: Timestamp {
            packed_date: 16581585,
            seconds: 59,
            nanos: 1000001000,
        },
        prev_time: Timestamp {
            packed_date: 81925857,
            seconds: 86399,
            nanos: 1000000,
        },
        next_oid: 18446744073709551615,
        next_lid: 0,
        next_twap_id: 127,
        system_nonce: 128,
        use_system_nonce: true,
        mac: 4294967295,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2024-03-01T00:00:60.000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "+10000-12-31T23:59:59.001"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dccff92cd0100cdffffce00010000ceffffffffcf0000000100000000ba323032342d30332d30315430303a30303a36302e303030303031b92b31303030302d31322d33315432333a35393a35392e303031cfffffffffffffffff007fcc80c3ceffffffff"
        )
    );
}
#[test]
fn boundary_13_map() {
    let ctx = Context {
        hardfork_height: 255,
        hardfork: Hardfork {
            version: 256,
            round: 65535,
        },
        height: 65536,
        tx_index: Some(4294967295),
        round: 4294967296,
        time: Timestamp {
            packed_date: 16581585,
            seconds: 59,
            nanos: 1000001000,
        },
        prev_time: Timestamp {
            packed_date: 81925857,
            seconds: 86399,
            nanos: 1000000,
        },
        next_oid: 18446744073709551615,
        next_lid: 0,
        next_twap_id: 127,
        system_nonce: 128,
        use_system_nonce: true,
        mac: 4294967295,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2024-03-01T00:00:60.000001"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "+10000-12-31T23:59:59.001"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874ccffa868617264666f726b82a776657273696f6ecd0100a5726f756e64cdffffa6686569676874ce00010000a874785f696e646578ceffffffffa5726f756e64cf0000000100000000a474696d65ba323032342d30332d30315430303a30303a36302e303030303031a9707265765f74696d65b92b31303030302d31322d33315432333a35393a35392e303031a86e6578745f6f6964cfffffffffffffffffa86e6578745f6c696400ac6e6578745f747761705f69647fac73797374656d5f6e6f6e6365cc80b07573655f73797374656d5f6e6f6e6365c3a36d6163ceffffffff"
        )
    );
}
#[test]
fn boundary_14_sequence() {
    let ctx = Context {
        hardfork_height: 256,
        hardfork: Hardfork {
            version: 65535,
            round: 65536,
        },
        height: 4294967295,
        tx_index: None,
        round: 18446744073709551615,
        time: Timestamp {
            packed_date: 16580625,
            seconds: 0,
            nanos: 999999000,
        },
        prev_time: Timestamp {
            packed_date: -81919039,
            seconds: 45296,
            nanos: 123456789,
        },
        next_oid: 0,
        next_lid: 127,
        next_twap_id: 128,
        system_nonce: 255,
        use_system_nonce: false,
        mac: 4294967296,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2024-01-01T00:00:00.999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "-10000-02-29T12:34:56.123456789"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcd010092cdffffce00010000ceffffffffc0cfffffffffffffffffba323032342d30312d30315430303a30303a30302e393939393939bf2d31303030302d30322d32395431323a33343a35362e313233343536373839007fcc80ccffc2cf0000000100000000"
        )
    );
}
#[test]
fn boundary_14_map() {
    let ctx = Context {
        hardfork_height: 256,
        hardfork: Hardfork {
            version: 65535,
            round: 65536,
        },
        height: 4294967295,
        tx_index: None,
        round: 18446744073709551615,
        time: Timestamp {
            packed_date: 16580625,
            seconds: 0,
            nanos: 999999000,
        },
        prev_time: Timestamp {
            packed_date: -81919039,
            seconds: 45296,
            nanos: 123456789,
        },
        next_oid: 0,
        next_lid: 127,
        next_twap_id: 128,
        system_nonce: 255,
        use_system_nonce: false,
        mac: 4294967296,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2024-01-01T00:00:00.999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "-10000-02-29T12:34:56.123456789"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cd0100a868617264666f726b82a776657273696f6ecdffffa5726f756e64ce00010000a6686569676874ceffffffffa874785f696e646578c0a5726f756e64cfffffffffffffffffa474696d65ba323032342d30312d30315430303a30303a30302e393939393939a9707265765f74696d65bf2d31303030302d30322d32395431323a33343a35362e313233343536373839a86e6578745f6f696400a86e6578745f6c69647fac6e6578745f747761705f6964cc80ac73797374656d5f6e6f6e6365ccffb07573655f73797374656d5f6e6f6e6365c2a36d6163cf0000000100000000"
        )
    );
}
#[test]
fn boundary_15_sequence() {
    let ctx = Context {
        hardfork_height: 65535,
        hardfork: Hardfork {
            version: 65536,
            round: 4294967295,
        },
        height: 4294967296,
        tx_index: Some(18446744073709551615),
        round: 0,
        time: Timestamp {
            packed_date: 16580625,
            seconds: 86399,
            nanos: 1999999000,
        },
        prev_time: Timestamp {
            packed_date: 16384961,
            seconds: 59,
            nanos: 1999999999,
        },
        next_oid: 127,
        next_lid: 128,
        next_twap_id: 255,
        system_nonce: 256,
        use_system_nonce: true,
        mac: 18446744073709551615,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2024-01-01T23:59:60.999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2000-02-29T00:00:60.999999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Sequence).unwrap(),
        unhex(
            "9dcdffff92ce00010000ceffffffffcf0000000100000000cfffffffffffffffff00ba323032342d30312d30315432333a35393a36302e393939393939bd323030302d30322d32395430303a30303a36302e3939393939393939397fcc80ccffcd0100c3cfffffffffffffffff"
        )
    );
}
#[test]
fn boundary_15_map() {
    let ctx = Context {
        hardfork_height: 65535,
        hardfork: Hardfork {
            version: 65536,
            round: 4294967295,
        },
        height: 4294967296,
        tx_index: Some(18446744073709551615),
        round: 0,
        time: Timestamp {
            packed_date: 16580625,
            seconds: 86399,
            nanos: 1999999000,
        },
        prev_time: Timestamp {
            packed_date: 16384961,
            seconds: 59,
            nanos: 1999999999,
        },
        next_oid: 127,
        next_lid: 128,
        next_twap_id: 255,
        system_nonce: 256,
        use_system_nonce: true,
        mac: 18446744073709551615,
    };
    assert_eq!(
        timestamp_text(ctx.time).unwrap(),
        "2024-01-01T23:59:60.999999"
    );
    assert_eq!(
        timestamp_text(ctx.prev_time).unwrap(),
        "2000-02-29T00:00:60.999999999"
    );
    assert_eq!(
        encode(&ctx, Mode::Map).unwrap(),
        unhex(
            "8daf68617264666f726b5f686569676874cdffffa868617264666f726b82a776657273696f6ece00010000a5726f756e64ceffffffffa6686569676874cf0000000100000000a874785f696e646578cfffffffffffffffffa5726f756e6400a474696d65ba323032342d30312d30315432333a35393a36302e393939393939a9707265765f74696d65bd323030302d30322d32395430303a30303a36302e393939393939393939a86e6578745f6f69647fa86e6578745f6c6964cc80ac6e6578745f747761705f6964ccffac73797374656d5f6e6f6e6365cd0100b07573655f73797374656d5f6e6f6e6365c3a36d6163cfffffffffffffffff"
        )
    );
}
#[test]
fn raw_timestamp_validation_is_not_a_native_error_claim() {
    for t in [
        Timestamp {
            packed_date: 733 << 3,
            seconds: 0,
            nanos: 0,
        },
        Timestamp {
            packed_date: 16,
            seconds: 86400,
            nanos: 0,
        },
        Timestamp {
            packed_date: 16,
            seconds: 0,
            nanos: 2000000000,
        },
    ] {
        assert_eq!(timestamp_text(t), Err(OutsideTimestampProfile));
    }
}
#[test]
fn captured_low_three_date_flags_do_not_affect_text() {
    let a = Timestamp {
        packed_date: 16,
        seconds: 59,
        nanos: 1000000001,
    };
    for flag in 0..8 {
        assert_eq!(
            timestamp_text(Timestamp {
                packed_date: a.packed_date | flag,
                ..a
            }),
            timestamp_text(a)
        );
    }
}
