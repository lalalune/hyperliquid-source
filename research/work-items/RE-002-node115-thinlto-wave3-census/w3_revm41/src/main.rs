use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_revm41_alloy21(arg: &str) {
    use revm::{
        context::{BlockEnv, CfgEnv, TxEnv},
        database::{CacheDB, EmptyDB},
        primitives::{Address, Bytes, TxKind, U256},
        Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext,
    };

    // Exercise revm 41.0.0 full mainnet EVM execution (Call + Create + Prague/Cancun + precompiles)
    let mut db = CacheDB::new(EmptyDB::default());
    let caller = Address::from([0x11u8; 20]);
    let target = Address::from([0x22u8; 20]);
    let mut acc = revm::state::AccountInfo::default();
    acc.balance = U256::from(10_000_000_000_000_000_000u128);
    db.insert_account_info(caller, acc);
    // Deploy bytecode exercising arithmetic, memory, storage, sha3, call, log, create, precompiles
    let mut code = revm::state::AccountInfo::default();
    code.code = Some(revm::bytecode::Bytecode::new_raw(Bytes::from_static(&[
        0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x55, // PUSH1 1 PUSH1 2 ADD PUSH1 0 SSTORE
        0x60, 0x20, 0x60, 0x00, 0x20, 0x60, 0x00, 0x52, // KECCAK256 MSTORE
        0x60, 0x20, 0x60, 0x00, 0xa1,                   // LOG1
        0x60, 0x20, 0x60, 0x00, 0xf3,                   // RETURN
    ])));
    db.insert_account_info(target, code);

    let mut evm = Context::mainnet()
        .with_db(db)
        .with_block(BlockEnv::default())
        .build_mainnet();

    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(target))
        .data(Bytes::copy_from_slice(arg.as_bytes()))
        .gas_limit(1_000_000)
        .build()
        .unwrap();
    let _ = core::hint::black_box(evm.transact_commit(tx));

    let tx_create = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Create)
        .data(Bytes::copy_from_slice(arg.as_bytes()))
        .gas_limit(1_000_000)
        .build()
        .unwrap();
    let _ = core::hint::black_box(evm.transact(tx_create));

    // Exercise ALL revm-precompile 41.0.0 precompiles directly
    for spec in [
        revm::precompile::PrecompileSpecId::HOMESTEAD,
        revm::precompile::PrecompileSpecId::BYZANTIUM,
        revm::precompile::PrecompileSpecId::ISTANBUL,
        revm::precompile::PrecompileSpecId::BERLIN,
        revm::precompile::PrecompileSpecId::CANCUN,
        revm::precompile::PrecompileSpecId::PRAGUE,
        revm::precompile::PrecompileSpecId::OSAKA,
    ] {
        let pre = revm::precompile::Precompiles::new(spec);
        for addr in pre.addresses() {
            if let Some(p) = pre.get(addr) {
                let _ = core::hint::black_box(p.execute(arg.as_bytes(), 1_000_000, 0));
            }
        }
    }

    // Exercise revm-bytecode analysis & jump table
    let bc = revm::bytecode::Bytecode::new_raw(Bytes::copy_from_slice(arg.as_bytes()));
    let _ = core::hint::black_box(revm::bytecode::Bytecode::new_legacy(bc.original_bytes()));

    // Exercise alloy-primitives 1.6.1 + alloy-rlp 0.3.16
    use alloy_rlp::{Decodable, Encodable};
    let mut rlp_buf = Vec::new();
    let addr_p = alloy_primitives::Address::from([0x33u8; 20]);
    let b256_p = alloy_primitives::keccak256(arg.as_bytes());
    let u256_p = alloy_primitives::U256::from_str_radix(arg, 10).unwrap_or(alloy_primitives::U256::from(12345u64));
    addr_p.encode(&mut rlp_buf);
    b256_p.encode(&mut rlp_buf);
    u256_p.encode(&mut rlp_buf);
    let mut sl = rlp_buf.as_slice();
    let _ = core::hint::black_box(alloy_primitives::Address::decode(&mut sl));
    let _ = core::hint::black_box(alloy_primitives::B256::decode(&mut sl));
    let _ = core::hint::black_box(alloy_primitives::U256::decode(&mut sl));

    // Exercise alloy-consensus 2.1.1 transactions, header, receipt, eip2718
    let hdr: Result<alloy_consensus::Header, _> = serde_json::from_str(arg);
    if let Ok(h) = hdr {
        let mut out = Vec::new();
        h.encode(&mut out);
        let _ = core::hint::black_box((h.hash_slow(), serde_json::to_string(&h), out));
    }
    let tx_leg: Result<alloy_consensus::TxLegacy, _> = serde_json::from_str(arg);
    if let Ok(t) = tx_leg {
        let mut out = Vec::new();
        t.encode(&mut out);
        let _ = core::hint::black_box((serde_json::to_string(&t), out));
    }
    let tx_2930: Result<alloy_consensus::TxEip2930, _> = serde_json::from_str(arg);
    if let Ok(t) = tx_2930 {
        let mut out = Vec::new();
        t.encode(&mut out);
        let _ = core::hint::black_box((serde_json::to_string(&t), out));
    }
    let tx_1559: Result<alloy_consensus::TxEip1559, _> = serde_json::from_str(arg);
    if let Ok(t) = tx_1559 {
        let mut out = Vec::new();
        t.encode(&mut out);
        let _ = core::hint::black_box((serde_json::to_string(&t), out));
    }
    let tx_4844: Result<alloy_consensus::TxEip4844, _> = serde_json::from_str(arg);
    if let Ok(t) = tx_4844 {
        let mut out = Vec::new();
        t.encode(&mut out);
        let _ = core::hint::black_box((serde_json::to_string(&t), out));
    }
    let tx_7702: Result<alloy_consensus::TxEip7702, _> = serde_json::from_str(arg);
    if let Ok(t) = tx_7702 {
        let mut out = Vec::new();
        t.encode(&mut out);
        let _ = core::hint::black_box((serde_json::to_string(&t), out));
    }
    let tx_env: Result<alloy_consensus::TxEnvelope, _> = alloy_eips::eip2718::Decodable2718::decode_2718(&mut arg.as_bytes());
    if let Ok(e) = tx_env {
        let mut out = Vec::new();
        alloy_eips::eip2718::Encodable2718::encode_2718(&e, &mut out);
        let _ = core::hint::black_box((serde_json::to_string(&e), out));
    }
    let rec: Result<alloy_consensus::ReceiptEnvelope, _> = serde_json::from_str(arg);
    let _ = core::hint::black_box(rec);

    // Exercise alloy-rpc-types-eth 2.1.1
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Filter>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionRequest>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Transaction>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Log>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Header>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::FeeHistory>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::AccessListResult>(arg));

    // Exercise alloy-trie 0.9.5 + nybbles 0.4.8 (HashBuilder, ProofRetainer, BranchNode, LeafNode, root)
    let mut retainer = alloy_trie::proof::ProofRetainer::from_iter([
        nybbles::Nibbles::unpack(b256_p),
        nybbles::Nibbles::unpack(alloy_primitives::B256::ZERO),
    ]);
    let mut hb = alloy_trie::HashBuilder::default().with_proof_retainer(retainer);
    hb.add_leaf(nybbles::Nibbles::unpack(alloy_primitives::B256::ZERO), b"val0");
    hb.add_leaf(nybbles::Nibbles::unpack(b256_p), arg.as_bytes());
    let root = hb.root();
    let proof = hb.take_proof_nodes();
    let _ = core::hint::black_box((root, proof));
    let _ = core::hint::black_box(alloy_trie::root::storage_root_unhashed(vec![
        (alloy_primitives::B256::ZERO, alloy_primitives::U256::from(1u64)),
        (b256_p, u256_p),
    ]));
    let mut b_sl = arg.as_bytes();
    let _ = core::hint::black_box(alloy_trie::nodes::TrieNode::decode(&mut b_sl));
    let mut nib = nybbles::Nibbles::from_nibbles_unchecked([1, 2, 3, 4, 5, 6]);
    nib.push(7);
    let _ = core::hint::black_box((nib.pack(), nib.common_prefix_length(&nybbles::Nibbles::unpack(b256_p))));

    // Exercise alloy-sol-types 1.6.1 ABI encoding/decoding
    use alloy_sol_types::SolValue;
    let tup = (addr_p, u256_p, b256_p, arg.to_string(), vec![1u64, 2, 3]);
    let enc = tup.abi_encode();
    let enc_p = tup.abi_encode_packed();
    let dec = <(alloy_primitives::Address, alloy_primitives::U256, alloy_primitives::B256, String, Vec<u64>)>::abi_decode(&enc);
    let _ = core::hint::black_box((enc_p, dec));

    // Exercise keccak-asm 0.1.6
    use keccak_asm::Digest;
    let mut kh = keccak_asm::Keccak256::new();
    kh.update(arg.as_bytes());
    let _ = core::hint::black_box(kh.finalize());
}

#[inline(never)]
fn touch_net_crypto_runtime(arg: &str) {
    // k256 0.13.4 ECDSA sign/verify/recover + ECDH
    {
        use k256::ecdsa::{signature::Signer, signature::Verifier, RecoveryId, Signature, SigningKey, VerifyingKey};
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let vk = VerifyingKey::from(&sk);
        let sig: Signature = sk.sign(arg.as_bytes());
        let _ = core::hint::black_box(vk.verify(arg.as_bytes(), &sig));
        let (sig2, recid) = sk.sign_prehash_recoverable(&[0x11u8; 32]).unwrap();
        let _ = core::hint::black_box(VerifyingKey::recover_from_prehash(&[0x11u8; 32], &sig2, recid));
        let _ = core::hint::black_box(VerifyingKey::recover_from_prehash(&[0x11u8; 32], &sig2, RecoveryId::from_byte(0).unwrap()));
        let sec = k256::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let pk = sec.public_key();
        let _ = core::hint::black_box(k256::ecdh::diffie_hellman(sec.to_nonzero_scalar(), pk.as_affine()));
    }

    // p256 0.13.2 ECDSA sign/verify/recover
    {
        use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
        let sk = SigningKey::from_slice(&[0x24u8; 32]).unwrap();
        let vk = VerifyingKey::from(&sk);
        let sig: Signature = sk.sign(arg.as_bytes());
        let _ = core::hint::black_box(vk.verify(arg.as_bytes(), &sig));
        let (sig2, recid) = sk.sign_prehash_recoverable(&[0x22u8; 32]).unwrap();
        let _ = core::hint::black_box(VerifyingKey::recover_from_prehash(&[0x22u8; 32], &sig2, recid));
    }

    // blst 0.3.16 min_pk + min_sig + multi-scalar pippenger
    {
        let sk = blst::min_pk::SecretKey::key_gen(&[0x55u8; 32], &[]).unwrap();
        let pk = sk.sk_to_pk();
        let sig = sk.sign(arg.as_bytes(), b"BLS_SIG", &[]);
        let _ = core::hint::black_box(sig.verify(true, arg.as_bytes(), b"BLS_SIG", &[], &pk, true));
        let agg = blst::min_pk::AggregateSignature::aggregate(&[&sig], true);
        let agg_pk = blst::min_pk::AggregatePublicKey::aggregate(&[&pk], true);
        let _ = core::hint::black_box((agg, agg_pk));
        let sk2 = blst::min_sig::SecretKey::key_gen(&[0x66u8; 32], &[]).unwrap();
        let pk2 = sk2.sk_to_pk();
        let sig2 = sk2.sign(arg.as_bytes(), b"BLS_SIG", &[]);
        let _ = core::hint::black_box(sig2.verify(true, arg.as_bytes(), b"BLS_SIG", &[], &pk2, true));
    }

    // rayon 1.12.0 + rayon-core 1.13.0 + crossbeam-deque 0.8.6 + crossbeam-epoch 0.9.20
    {
        use rayon::prelude::*;
        let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
        pool.install(|| {
            let mut v: Vec<u64> = (0..512u64).into_par_iter().map(|x| x.wrapping_mul(7)).collect();
            v.par_sort();
            v.par_sort_unstable();
            let _ = core::hint::black_box(v.par_chunks(16).map(|c| c.iter().sum::<u64>()).sum::<u64>());
        });
        let w = crossbeam_deque::Worker::<u64>::new_fifo();
        w.push(1);
        w.push(2);
        let s = w.stealer();
        let _ = core::hint::black_box((w.pop(), s.steal()));
        let guard = crossbeam_epoch::pin();
        let a = crossbeam_epoch::Atomic::new(42u64);
        let _ = core::hint::black_box(a.load(std::sync::atomic::Ordering::Acquire, &guard));
    }

    // chrono 0.4.41 + url 2.5.8 + idna 1.1.0 + icu_normalizer 2.0.1 + lz4_flex 0.12.1 + bitvec + blake3 1.8.5 + sha2 0.10.9
    {
        let dt = chrono::Utc::now();
        let loc = chrono::Local::now();
        let _ = core::hint::black_box((
            dt.to_rfc3339(),
            dt.to_rfc2822(),
            loc.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string(),
            chrono::DateTime::parse_from_rfc3339(arg),
            chrono::DateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S %z"),
            chrono::NaiveDateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S"),
        ));
        let _ = core::hint::black_box(url::Url::parse(arg));
        let _ = core::hint::black_box(idna::domain_to_ascii(arg));
        let nfc = icu_normalizer::ComposingNormalizer::new_nfc();
        let _ = core::hint::black_box(nfc.normalize(arg));
        let comp = lz4_flex::compress_prepend_size(arg.as_bytes());
        let _ = core::hint::black_box(lz4_flex::decompress_size_prepended(&comp));
        let mut bv = bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::repeat(false, 256);
        bv.set(7, true);
        let _ = core::hint::black_box((bv.count_ones(), bv.first_one()));
        let _ = core::hint::black_box(blake3::hash(arg.as_bytes()));
        use sha2::Digest;
        let _ = core::hint::black_box((sha2::Sha256::digest(arg.as_bytes()), sha2::Sha512::digest(arg.as_bytes())));
        let mut hdrs = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut hdrs);
        let _ = core::hint::black_box(req.parse(arg.as_bytes()));
        let _ = core::hint::black_box(httpdate::parse_http_date(arg));
    }

    // jsonrpsee-core 0.26.0 + tokio 1.52.3 + hyper 1.10.1 + h2 0.4.14 + bytes 1.12.1
    {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let s = arg.to_string();
        rt.block_on(async move {
            let mut module = jsonrpsee_core::server::RpcModule::new(());
            let _ = module.register_method("eth_blockNumber", |_, _, _| "0x1");
            let _ = module.register_async_method("eth_call", |params, _, _| async move {
                let _: Result<serde_json::Value, _> = params.one();
                "0x"
            });
            let _ = core::hint::black_box(module.raw_json_request(&s, 1).await);
            let mut bm = bytes::BytesMut::with_capacity(128);
            bm.extend_from_slice(s.as_bytes());
            let b = bm.freeze();
            let _ = core::hint::black_box(b.slice(0..b.len().min(4)));
            if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
                let _ = h2::client::handshake(stream).await;
            }
            let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
            let _ = tx.send(s).await;
            let _ = core::hint::black_box(rx.recv().await);
        });
    }
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "test".to_string());
    if arg == "__never__" {
        touch_revm41_alloy21(&arg);
        touch_net_crypto_runtime(&arg);
    }
}
