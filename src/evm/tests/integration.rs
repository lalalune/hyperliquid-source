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
