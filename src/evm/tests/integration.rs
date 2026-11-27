use evm::{
    admit_mode13_gas, compute_mode13_gas, execute_l1_block_number_precompile, fold_child_reserve,
    is_scaled_precompile_active, read_precompile_address, read_precompile_fixed_output_len,
    read_precompile_preflight_gas, read_precompile_total_gas, restore_transient_journal,
    run_scaled_precompile, scaled_precompile_divisor, CallResultWords, EvmDbKeyspace, EvmLtHashes,
    FrameWords, LtHash, Mode13GasAdmission, Mode13GasInput, Node115EvmTransactionType,
    ReadPrecompileOutcomeName, ReadPrecompileOutput, ReadPrecompileResultKind,
    ScaledPrecompileError, TransientJournal, TransientStorage, READ_PRECOMPILE_MAX_INPUT_LEN,
    READ_PRECOMPILE_SUFFIXES, SCALED_PRECOMPILES,
};

#[test]
fn read_precompiles_21_addresses_and_gas_formula() {
    assert_eq!(READ_PRECOMPILE_SUFFIXES.len(), 21);
    assert_eq!(READ_PRECOMPILE_SUFFIXES[0], 0x0800);
    assert_eq!(READ_PRECOMPILE_SUFFIXES[1], 0x0813);
    assert_eq!(READ_PRECOMPILE_SUFFIXES[20], 0x0814);

    // Boundary on max input len 2000 (0x7d0):
    assert_eq!(read_precompile_preflight_gas(0), Some(1000));
    assert_eq!(
        read_precompile_preflight_gas(READ_PRECOMPILE_MAX_INPUT_LEN),
        Some(1000 + 33 * 2000)
    );
    assert_eq!(
        read_precompile_preflight_gas(READ_PRECOMPILE_MAX_INPUT_LEN + 1),
        None
    );

    // Fixed output lengths match exact node #115 post-output gas immediates:
    assert_eq!(read_precompile_fixed_output_len(0x0800), Some(160));
    assert_eq!(read_precompile_total_gas(0, 160), Some(6280)); // 0x1888
    assert_eq!(read_precompile_fixed_output_len(0x0801), Some(96));
    assert_eq!(read_precompile_total_gas(0, 96), Some(4168)); // 0x1048
    assert_eq!(read_precompile_fixed_output_len(0x0802), Some(64));
    assert_eq!(read_precompile_total_gas(0, 64), Some(3112)); // 0x0c28
    assert_eq!(read_precompile_fixed_output_len(0x0805), Some(128));
    assert_eq!(read_precompile_total_gas(0, 128), Some(5224)); // 0x1468
    assert_eq!(read_precompile_fixed_output_len(0x0809), Some(32));
    assert_eq!(read_precompile_total_gas(0, 32), Some(2056)); // 0x0808

    // L1BlockNumber (0x0809 / 0x38e3b40) exact boundary behavior:
    assert_eq!(read_precompile_address(0x0809)[18..], [0x08, 0x09]);
    assert_eq!(
        execute_l1_block_number_precompile(&[], 2055, 12345),
        ReadPrecompileOutput::OutOfGas
    );
    let ok = execute_l1_block_number_precompile(&[], 2056, 0x0102_0304_0506_0708);
    assert_eq!(ok.outcome_name(), ReadPrecompileOutcomeName::Ok);
    match ok {
        ReadPrecompileOutput::Ok { gas_used, bytes } => {
            assert_eq!(gas_used, 2056);
            assert_eq!(bytes.len(), 32);
            assert_eq!(&bytes[..24], &[0u8; 24]);
            assert_eq!(&bytes[24..], &0x0102_0304_0506_0708u64.to_be_bytes());
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(
        execute_l1_block_number_precompile(&vec![0u8; 2001], u64::MAX, 1),
        ReadPrecompileOutput::OutOfGas
    );
}

#[test]
fn scaled_precompiles_and_activation_predicate() {
    assert_eq!(SCALED_PRECOMPILES.len(), 7);
    let mut blake2f = [0u8; 20];
    blake2f[19] = 0x09;
    assert_eq!(scaled_precompile_divisor(&blake2f), Some(10));
    let (cost, out) = run_scaled_precompile(&blake2f, 120, |g| {
        assert_eq!(g, 12);
        Ok((12, 42u8))
    })
    .unwrap();
    assert_eq!((cost, out), (120, 42));

    // Overflow saturates to u64::MAX (0x2a6b6e6):
    let (sat_cost, _) = run_scaled_precompile(&blake2f, u64::MAX, |_| Ok((u64::MAX, ()))).unwrap();
    assert_eq!(sat_cost, u64::MAX);

    let mut non_scaled = [0u8; 20];
    non_scaled[19] = 0x02;
    assert_eq!(
        run_scaled_precompile(&non_scaled, 1000, |_| Ok((1, ()))),
        Err(ScaledPrecompileError::NotScaled)
    );

    assert_eq!(is_scaled_precompile_active(1, 9, 10), Some(true));
    assert_eq!(is_scaled_precompile_active(1, 8, 10), Some(false));
    assert_eq!(is_scaled_precompile_active(0, 100, 10), Some(false));
    assert_eq!(is_scaled_precompile_active(1, u64::MAX, 1), None);
}

#[test]
fn mode13_intrinsic_gas_matches_re021_preflight_vector() {
    // Exact synthetic vector from RE-021-precompile-preflight-115:
    // 213 bytes with 211 zeros and 2 nonzeros -> initial=21876, floor=23190.
    let mut data = vec![0u8; 213];
    data[3] = 12;
    data[212] = 1;
    let bd = compute_mode13_gas(Mode13GasInput::from_calldata(&data, false)).unwrap();
    assert_eq!(bd.tokens, 219);
    assert_eq!(bd.initial, 21_876);
    assert_eq!(bd.floor, 23_190);
    assert_eq!(
        admit_mode13_gas(bd, 21_875, false),
        Mode13GasAdmission::InitialExceedsLimit
    );
    assert_eq!(
        admit_mode13_gas(bd, 21_876, false),
        Mode13GasAdmission::FloorExceedsLimit
    );
    assert_eq!(
        admit_mode13_gas(bd, 23_189, false),
        Mode13GasAdmission::FloorExceedsLimit
    );
    assert_eq!(
        admit_mode13_gas(bd, 23_190, false),
        Mode13GasAdmission::Admitted
    );
}

#[test]
fn lt_hash_1024_big_endian_u16_lanes_and_joined_micro_crates() {
    let mut a = LtHash::zero();
    let mut b = LtHash::zero();
    // Lane 0: 0xffff + 0x0002 = 0x0001 (wraps within 16-bit lane, no carry into lane 1!)
    a.hash[0..2].copy_from_slice(&0xffffu16.to_be_bytes());
    b.hash[0..2].copy_from_slice(&0x0002u16.to_be_bytes());
    a.n_elements = u64::MAX;
    b.n_elements = 5;
    a.n_bytes = 100;
    b.n_bytes = 250;
    a.merge_assign(&b);
    assert_eq!(&a.hash[0..2], &0x0001u16.to_be_bytes());
    assert_eq!(&a.hash[2..4], &0x0000u16.to_be_bytes());
    assert_eq!(a.n_elements, u64::MAX);
    assert_eq!(a.n_bytes, 350);

    let hashes = EvmLtHashes {
        accounts_hash: a,
        contracts_hash: LtHash::zero(),
        storage_hash: LtHash::zero(),
    };
    let json = hashes.to_json_string();
    assert!(json.starts_with(r#"{"accounts_hash":{"n_elements":18446744073709551615,"n_bytes":350,"hash":[0,1,0,0"#));
    assert!(json.contains(r#""contracts_hash":"#));
    assert!(json.contains(r#""storage_hash":"#));

    // Verify all 3 keyspaces and joined micro-crates:
    assert_eq!(EvmDbKeyspace::Accounts.prefix(), b"Ea");
    assert_eq!(EvmDbKeyspace::Contracts.prefix(), b"Ec");
    assert_eq!(EvmDbKeyspace::Storage.prefix(), b"Es");
    assert_eq!(
        Node115EvmTransactionType::from_bytes(b"Eip7702"),
        Some(Node115EvmTransactionType::Eip7702)
    );
    assert_eq!(
        ReadPrecompileResultKind::from_bytes(b"OutOfGas"),
        Some(ReadPrecompileResultKind::OutOfGas)
    );
    let mut frame = FrameWords {
        word_190: 10,
        word_198: 5,
    };
    fold_child_reserve(
        &mut frame,
        CallResultWords {
            word_58: 3,
            word_60: -1,
            raw_status_70: 1,
        },
    )
    .unwrap();
    assert_eq!(frame, FrameWords { word_190: 3, word_198: 4 });
    let mut transient = TransientStorage::new();
    restore_transient_journal(
        Some(&mut transient),
        &TransientJournal {
            address: [1; 20],
            key: [2; 32],
            old: [3; 32],
        },
    );
    assert_eq!(transient[&[1; 20]][&[2; 32]], [3; 32]);
}

#[test]
fn dual_block_gas_limits_system_contracts_and_core_writer_frame() {
    use evm::{
        encode_core_writer_frame, is_core_writer_action_id_active, parse_core_writer_frame,
        read_precompile_input_decoder, CoreWriterFrameError, EvmBlockKind,
        ReadPrecompileInputDecoder, BIG_BLOCK_GAS_LIMIT, CORE_WRITER_ACTIVE_ACTION_IDS,
        CORE_WRITER_ADDRESS, CORE_WRITER_MAX_RAW_LEN, CORE_WRITER_VERSION_V1,
        HYPER_EVM_SYSTEM_CONTRACTS, HYPE_SYSTEM_ADDRESS, SMALL_BLOCK_GAS_LIMIT,
        WHYPE_SYSTEM_ADDRESS,
    };

    assert_eq!(SMALL_BLOCK_GAS_LIMIT, 3_000_000);
    assert_eq!(BIG_BLOCK_GAS_LIMIT, 30_000_000);
    assert_eq!(EvmBlockKind::from_using_big_blocks(false).gas_limit(), 3_000_000);
    assert_eq!(EvmBlockKind::from_using_big_blocks(true).gas_limit(), 30_000_000);
    assert_eq!(EvmBlockKind::Small.guard_pair(), (0.03, 0.07));
    assert_eq!(EvmBlockKind::Big.guard_pair(), (0.05, 0.05));

    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS.len(), 3);
    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS[0].address, CORE_WRITER_ADDRESS);
    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS[0].bytecode_len, 544);
    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS[1].address, HYPE_SYSTEM_ADDRESS);
    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS[1].bytecode_len, 122);
    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS[2].address, WHYPE_SYSTEM_ADDRESS);
    assert_eq!(HYPER_EVM_SYSTEM_CONTRACTS[2].bytecode_len, 2041);

    // CoreWriter v1 boundary checks:
    assert_eq!(
        parse_core_writer_frame(&[], |_, _| false),
        Err(CoreWriterFrameError::LengthOutOfRange(0))
    );
    assert_eq!(
        parse_core_writer_frame(&[1, 0, 1], |_, _| false),
        Err(CoreWriterFrameError::HeaderTooShort(3))
    );
    assert_eq!(
        parse_core_writer_frame(&vec![1; CORE_WRITER_MAX_RAW_LEN + 1], |_, _| false),
        Err(CoreWriterFrameError::LengthOutOfRange(1001))
    );
    // Disabled check runs before version/action_id check (0x38bf4e5 before 0x38bf508):
    assert_eq!(
        parse_core_writer_frame(&[2, 0, 0, 14], |v, a| v == 2 && a == 14),
        Err(CoreWriterFrameError::ActionDisabled {
            version: 2,
            action_id: 14,
        })
    );
    assert_eq!(
        parse_core_writer_frame(&[2, 0, 0, 1], |_, _| false),
        Err(CoreWriterFrameError::UnsupportedVersion(2))
    );
    assert!(!is_core_writer_action_id_active(0));
    assert!(!is_core_writer_action_id_active(14));
    assert!(!is_core_writer_action_id_active(18));
    assert_eq!(
        parse_core_writer_frame(&[1, 0, 0, 14], |_, _| false),
        Err(CoreWriterFrameError::UnsupportedActionId(14))
    );

    for aid in CORE_WRITER_ACTIVE_ACTION_IDS {
        assert!(is_core_writer_action_id_active(aid));
        let frame = encode_core_writer_frame(CORE_WRITER_VERSION_V1, aid, &[0xaa, 0xbb]).unwrap();
        let parsed = parse_core_writer_frame(&frame, |_, _| false).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.action_id, aid);
        assert_eq!(parsed.payload, &[0xaa, 0xbb]);
    }

    // All 21 read precompile suffixes classify cleanly into the 5 observed decoder families:
    for suffix in READ_PRECOMPILE_SUFFIXES {
        assert!(read_precompile_input_decoder(suffix).is_some());
    }
    assert_eq!(
        read_precompile_input_decoder(0x0809),
        Some(ReadPrecompileInputDecoder::Empty)
    );
    assert_eq!(
        read_precompile_input_decoder(0x0801),
        Some(ReadPrecompileInputDecoder::AddressAndUint)
    );
    assert_eq!(
        read_precompile_input_decoder(0x0806),
        Some(ReadPrecompileInputDecoder::SingleWordUint)
    );
    assert_eq!(
        read_precompile_input_decoder(0x0812),
        Some(ReadPrecompileInputDecoder::SingleWord3897200)
    );
    assert_eq!(
        read_precompile_input_decoder(0x0800),
        Some(ReadPrecompileInputDecoder::GenericEthAbi)
    );
    assert_eq!(read_precompile_input_decoder(0x0815), None);
}

#[test]
fn mode13_gas_boundary_overflow_and_create_word_rounding() {
    // CREATE initcode word rounding: 0 -> 0 words, 1..=32 -> 1 word, 33 -> 2 words.
    let base_create = compute_mode13_gas(Mode13GasInput {
        zero_bytes: 0,
        nonzero_bytes: 0,
        access_addresses: 0,
        access_slots: 0,
        auth_items: 0,
        is_create: true,
    })
    .unwrap();
    assert_eq!(base_create.initial, 53_000); // 21_000 + 32_000
    assert_eq!(base_create.floor, 21_000);

    let one_byte_create = compute_mode13_gas(Mode13GasInput::from_calldata(&[0u8; 1], true)).unwrap();
    assert_eq!(one_byte_create.tokens, 1);
    assert_eq!(one_byte_create.initial, 21_000 + 4 + 32_000 + 2);

    let thirty_three_create =
        compute_mode13_gas(Mode13GasInput::from_calldata(&[0u8; 33], true)).unwrap();
    assert_eq!(thirty_three_create.initial, 21_000 + 33 * 4 + 32_000 + 4);

    // Access list + EIP-7702 authorization items + floor-disabled admission override.
    let with_lists = compute_mode13_gas(Mode13GasInput {
        zero_bytes: 100,
        nonzero_bytes: 10,
        access_addresses: 2,
        access_slots: 3,
        auth_items: 1,
        is_create: false,
    })
    .unwrap();
    assert_eq!(with_lists.tokens, 140);
    assert_eq!(with_lists.initial, 21_000 + 560 + 4_800 + 5_700 + 25_000);
    assert_eq!(with_lists.floor, 22_400);

    // When floor > initial, disable_floor=true admits at gas_limit == initial.
    let heavy_calldata =
        compute_mode13_gas(Mode13GasInput::from_calldata(&[0xffu8; 10], false)).unwrap();
    assert!(heavy_calldata.floor > heavy_calldata.initial);
    assert_eq!(
        admit_mode13_gas(heavy_calldata, heavy_calldata.initial, false),
        Mode13GasAdmission::FloorExceedsLimit
    );
    assert_eq!(
        admit_mode13_gas(heavy_calldata, heavy_calldata.initial, true),
        Mode13GasAdmission::Admitted
    );

    // Overflowing input counts fail closed with None instead of wrapping.
    assert_eq!(
        compute_mode13_gas(Mode13GasInput {
            nonzero_bytes: u64::MAX,
            ..Mode13GasInput::default()
        }),
        None
    );
    assert_eq!(
        compute_mode13_gas(Mode13GasInput {
            auth_items: u64::MAX,
            ..Mode13GasInput::default()
        }),
        None
    );
}

#[test]
fn precompiles_lt_hash_full_lanes_and_core_writer_encoder_boundaries() {
    use evm::{
        encode_core_writer_frame, erase_transient_controls, parse_core_writer_frame,
        CoreWriterFrameError, TransientInvalidControls, CORE_WRITER_MAX_RAW_LEN,
        CORE_WRITER_VERSION_V1,
    };

    // Verify all 7 scaled precompile addresses, exact divisors, and callback error propagation.
    for &(last_byte, expected_div) in &SCALED_PRECOMPILES {
        let mut addr = [0u8; 20];
        addr[19] = last_byte;
        assert_eq!(scaled_precompile_divisor(&addr), Some(expected_div));
        let (cost, ()) = run_scaled_precompile(&addr, expected_div * 100, |limit| {
            assert_eq!(limit, 100);
            Ok((7, ()))
        })
        .unwrap();
        assert_eq!(cost, 7 * expected_div);
        assert_eq!(
            run_scaled_precompile::<()>(&addr, 100, |_| Err(())),
            Err(ScaledPrecompileError::CallbackError)
        );
    }
    // Non-zero upper bytes in address must never match scaled precompiles.
    let mut polluted_addr = [0u8; 20];
    polluted_addr[0] = 1;
    polluted_addr[19] = 0x01;
    assert_eq!(scaled_precompile_divisor(&polluted_addr), None);

    // Read precompile total gas overflow and nonzero-input L1BlockNumber boundary.
    assert_eq!(read_precompile_total_gas(0, usize::MAX), None);
    let input_10 = [0xabu8; 10];
    let exact_gas = 1000 + 33 * (10 + 32);
    assert_eq!(
        execute_l1_block_number_precompile(&input_10, exact_gas - 1, 77),
        ReadPrecompileOutput::OutOfGas
    );
    assert_eq!(
        execute_l1_block_number_precompile(&input_10, exact_gas, 77).outcome_name(),
        ReadPrecompileOutcomeName::Ok
    );

    // LtHash zero identity and all-1024-lane independent big-endian u16 wrapping.
    let mut x = LtHash::zero();
    let mut y = LtHash::zero();
    for lane in 0..evm::LT_HASH_LANES {
        let off = lane * 2;
        x.hash[off..off + 2].copy_from_slice(&(0xfffe_u16.wrapping_sub(lane as u16)).to_be_bytes());
        y.hash[off..off + 2].copy_from_slice(&((lane as u16).wrapping_add(5)).to_be_bytes());
    }
    x.merge_assign(&LtHash::zero());
    x.merge_assign(&y);
    for lane in 0..evm::LT_HASH_LANES {
        let off = lane * 2;
        assert_eq!(u16::from_be_bytes([x.hash[off], x.hash[off + 1]]), 3);
    }

    // CoreWriter encoder rejects >24-bit action IDs and payloads pushing frame past 1000 bytes.
    assert_eq!(encode_core_writer_frame(1, 0x0100_0000, &[]), None);
    assert_eq!(
        encode_core_writer_frame(1, 1, &vec![0u8; CORE_WRITER_MAX_RAW_LEN - 3]),
        None
    );
    let max_frame =
        encode_core_writer_frame(CORE_WRITER_VERSION_V1, 17, &vec![0x5a; CORE_WRITER_MAX_RAW_LEN - 4])
            .unwrap();
    assert_eq!(max_frame.len(), CORE_WRITER_MAX_RAW_LEN);
    let parsed = parse_core_writer_frame(&max_frame, |_, _| false).unwrap();
    assert_eq!(parsed.action_id, 17);
    assert_eq!(parsed.payload.len(), CORE_WRITER_MAX_RAW_LEN - 4);
    assert_eq!(
        parse_core_writer_frame(&[1, 0, 0, 0], |_, _| false),
        Err(CoreWriterFrameError::UnsupportedActionId(0))
    );

    // Transient rollback erase_controls & zero-restore micro-crate checks.
    let mut controls = vec![0xffu8; 48];
    controls[7] = 0x22;
    controls[39] = 0x22;
    let (mut growth, mut items) = (24u64, 1u64);
    assert_eq!(
        erase_transient_controls(&mut controls, 31, 7, &mut growth, &mut items),
        Ok(0xff)
    );
    assert_eq!((growth, items), (25, 0));
    assert_eq!(
        erase_transient_controls(&mut controls, 31, 7, &mut growth, &mut items),
        Err(TransientInvalidControls::NotOccupied)
    );
    let mut t = TransientStorage::new();
    t.entry([9; 20]).or_default().insert([8; 32], [7; 32]);
    restore_transient_journal(
        Some(&mut t),
        &TransientJournal {
            address: [9; 20],
            key: [8; 32],
            old: [0; 32],
        },
    );
    assert!(t.contains_key(&[9; 20]));
    assert!(t[&[9; 20]].is_empty());
}
