use bincode_fork::{ByteVec, DecodeError, decode_from_slice, encode_to_vec, standard};
use net_utils::gossip::greeting_encoder::{self, Detail, FixedPart, Greeting, SigMap, SigRow};
use net_utils::{
    AbciStreamGreeting, EvmKvsMsg, GreetingFixedPart, GreetingHash, WireSignature, read_bincode_frame,
    write_bincode_frame,
};
use std::io::Cursor;

#[test]
fn abci_stream_greeting_matches_node115_greeting_encoder_byte_for_byte() {
    let raw_sig = [0x11u8; 65];
    let wire_sig = WireSignature::from_bytes(raw_sig);
    assert_eq!(wire_sig.to_bytes(), raw_sig);

    // 1. Kind0 with Signatures
    let g_sig = AbciStreamGreeting::Kind0 {
        blob: ByteVec(vec![1, 2, 3, 4]),
        height: 42_000,
        hash: Box::new(GreetingHash::Signatures {
            first: [0xaa; 32],
            left: vec![wire_sig],
            right: vec![],
            last: [0xbb; 32],
        }),
    };
    let compat_sig = Greeting::Kind0 {
        blob: vec![1, 2, 3, 4],
        at_98: 42_000,
        detail: Box::new(Detail::Signatures {
            first: [0xaa; 32],
            left: vec![raw_sig],
            right: vec![],
            last: [0xbb; 32],
        }),
    };
    let bytes = encode_to_vec(&g_sig, standard()).unwrap();
    let compat_bytes = greeting_encoder::encode(&compat_sig).unwrap();
    assert_eq!(bytes, compat_bytes);
    let (decoded, used) = decode_from_slice::<AbciStreamGreeting>(&bytes, standard()).unwrap();
    assert_eq!(decoded, g_sig);
    assert_eq!(used, bytes.len());

    // 2. Kind0 with Maps
    let addr = [0x33u8; 20];
    let g_map = AbciStreamGreeting::Kind0 {
        blob: ByteVec(vec![]),
        height: 7,
        hash: Box::new(GreetingHash::Maps {
            first: [0x10; 32],
            left: vec![(addr, wire_sig)],
            right: vec![],
            last: [0x20; 32],
        }),
    };
    let sig_map = SigMap::tree(vec![SigRow {
        key: addr,
        sig: raw_sig,
    }]);
    let empty_map = SigMap::empty_ring();
    let compat_map = Greeting::Kind0 {
        blob: vec![],
        at_98: 7,
        detail: Box::new(Detail::Maps {
            first: [0x10; 32],
            left: sig_map,
            right: empty_map,
            last: [0x20; 32],
        }),
    };
    let map_bytes = encode_to_vec(&g_map, standard()).unwrap();
    assert_eq!(map_bytes, greeting_encoder::encode(&compat_map).unwrap());
    assert_eq!(
        decode_from_slice::<AbciStreamGreeting>(&map_bytes, standard()).unwrap().0,
        g_map
    );

    // 3. Kind0 with Fixed([FixedPart; 3])
    let part = GreetingFixedPart {
        field0: 100,
        field1: 200,
        bytes: [0x5a; 2048],
    };
    let g_fixed = AbciStreamGreeting::Kind0 {
        blob: ByteVec(b"chk".to_vec()),
        height: 999,
        hash: Box::new(GreetingHash::Fixed(Box::new([
            part.clone(),
            part.clone(),
            part,
        ]))),
    };
    let cpart = FixedPart {
        at_800: 100,
        at_808: 200,
        bytes: [0x5a; 2048],
    };
    let compat_fixed = Greeting::Kind0 {
        blob: b"chk".to_vec(),
        at_98: 999,
        detail: Box::new(Detail::Fixed(Box::new([
            cpart.clone(),
            cpart.clone(),
            cpart,
        ]))),
    };
    let fixed_bytes = encode_to_vec(&g_fixed, standard()).unwrap();
    assert_eq!(fixed_bytes, greeting_encoder::encode(&compat_fixed).unwrap());
    assert_eq!(
        decode_from_slice::<AbciStreamGreeting>(&fixed_bytes, standard()).unwrap().0,
        g_fixed
    );

    // 4. Kind1..Kind5 + InvalidBytesLength guard + UnexpectedVariant guard
    for (g, cg) in [
        (
            AbciStreamGreeting::Kind1 {
                field0: 1,
                field1: 500,
                field2: 100_000,
            },
            Greeting::Kind1 {
                at_18: 1,
                at_8: 500,
                at_10: 100_000,
            },
        ),
        (AbciStreamGreeting::Kind2, Greeting::Kind2),
        (AbciStreamGreeting::Kind3, Greeting::Kind3),
        (AbciStreamGreeting::Kind4, Greeting::Kind4),
        (AbciStreamGreeting::Kind5, Greeting::Kind5),
    ] {
        let w = encode_to_vec(&g, standard()).unwrap();
        assert_eq!(w, greeting_encoder::encode(&cg).unwrap());
        assert_eq!(decode_from_slice::<AbciStreamGreeting>(&w, standard()).unwrap().0, g);
    }

    // Truncated Kind0 blob triggers Hyperliquid fork tag 1 (InvalidBytesLength)
    let trunc_blob = [0u8, 200, 1, 2, 3]; // variant 0, blob len=200, only 3 bytes remaining
    assert_eq!(
        decode_from_slice::<AbciStreamGreeting>(&trunc_blob, standard()).unwrap_err(),
        DecodeError::InvalidBytesLength
    );

    // Unknown variant 6 triggers UnexpectedVariant (tag 5)
    let bad_var = decode_from_slice::<AbciStreamGreeting>(&[6], standard()).unwrap_err();
    assert_eq!(bad_var.tag(), 5);
}

#[test]
fn evm_kvs_msg_uncompressed_port_3998_stream_roundtrip_and_controls() {
    let batch = EvmKvsMsg::Batch(vec![
        (ByteVec(b"k1".to_vec()), ByteVec(vec![0xee; 2048])),
        (ByteVec(b"k2".to_vec()), ByteVec(b"v2".to_vec())),
    ]);
    let mut wire = Vec::new();
    // Port 3998 (EvmKvs) MUST NOT compress even when payload > 1025 bytes
    let (_, compressed1) = write_bincode_frame(&mut wire, &batch, 3998).unwrap();
    let (_, compressed2) = write_bincode_frame(&mut wire, &EvmKvsMsg::Done, 3998).unwrap();
    assert!(!compressed1);
    assert!(!compressed2);

    let mut cur = Cursor::new(wire);
    let m1: EvmKvsMsg = read_bincode_frame(&mut cur, 1_000_000, 1_000_000, Some(1_000_000)).unwrap();
    let m2: EvmKvsMsg = read_bincode_frame(&mut cur, 1_000_000, 1_000_000, Some(1_000_000)).unwrap();
    assert_eq!(m1, batch);
    assert_eq!(m2, EvmKvsMsg::Done);

    // Corruption controls: variant 2 rejected as UnexpectedVariant; truncated value rejected as InvalidBytesLength
    assert_eq!(
        decode_from_slice::<EvmKvsMsg>(&[2], standard()).unwrap_err().tag(),
        5
    );
    assert_eq!(
        decode_from_slice::<EvmKvsMsg>(&[0, 1, 2, b'a', b'b', 50, 1, 2], standard()).unwrap_err(),
        DecodeError::InvalidBytesLength
    );
}
