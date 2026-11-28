use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_revm43_alloy25(arg: &str) {
    use revm::{
        context::{BlockEnv, CfgEnv, TxEnv},
        database::{CacheDB, EmptyDB},
        primitives::{Address, Bytes, TxKind, U256},
        Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext,
    };

    let mut db = CacheDB::new(EmptyDB::default());
    let caller = Address::from([0x11u8; 20]);
    let target = Address::from([0x22u8; 20]);
    let mut acc = revm::state::AccountInfo::default();
    acc.balance = U256::from(10_000_000_000_000_000_000u128);
    db.insert_account_info(caller, acc);

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
    let tx_c = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Create)
        .data(Bytes::copy_from_slice(arg.as_bytes()))
        .gas_limit(1_000_000)
        .build()
        .unwrap();
    let _ = core::hint::black_box(evm.transact(tx_c));

    for spec in [
        revm::precompile::PrecompileSpecId::ISTANBUL,
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

    // alloy-consensus 2.5.0 + alloy-rpc-types-eth 2.5.0 + alloy-trie 0.9.9 + alloy-sol-types 1.7.3 + nybbles 0.4.9
    use alloy_rlp::{Decodable, Encodable};
    let b256 = alloy_primitives::keccak256(arg.as_bytes());
    let u256 = alloy_primitives::U256::from_str_radix(arg, 10).unwrap_or_default();
    let addr = alloy_primitives::Address::from([0x44u8; 20]);
    let mut rlp_buf = Vec::new();
    addr.encode(&mut rlp_buf);
    b256.encode(&mut rlp_buf);
    u256.encode(&mut rlp_buf);
    let _ = core::hint::black_box(rlp_buf);

    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::Header>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxLegacy>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxEip2930>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxEip1559>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxEip4844>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxEip7702>(arg));
    let _ = core::hint::black_box(alloy_eips::eip2718::Decodable2718::decode_2718(&mut arg.as_bytes()) as Result<alloy_consensus::TxEnvelope, _>);
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Filter>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionRequest>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Transaction>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionReceipt>(arg));

    let retainer = alloy_trie::proof::ProofRetainer::from_iter([nybbles::Nibbles::unpack(b256)]);
    let mut hb = alloy_trie::HashBuilder::default().with_proof_retainer(retainer);
    hb.add_leaf(nybbles::Nibbles::unpack(b256), arg.as_bytes());
    let _ = core::hint::black_box((hb.root(), hb.take_proof_nodes()));
    let mut sl = arg.as_bytes();
    let _ = core::hint::black_box(alloy_trie::nodes::TrieNode::decode(&mut sl));

    use alloy_sol_types::SolValue;
    let enc = (addr, u256, b256, arg.to_string()).abi_encode();
    let _ = core::hint::black_box(<(alloy_primitives::Address, alloy_primitives::U256, alloy_primitives::B256, String)>::abi_decode(&enc));

    use keccak_asm::Digest;
    let mut kh = keccak_asm::Keccak256::new();
    kh.update(arg.as_bytes());
    let _ = core::hint::black_box(kh.finalize());
}

#[inline(never)]
fn touch_deep_crypto_misc(arg: &str) {
    // curve25519-dalek-ng 4.1.1 (Edwards + Ristretto + Montgomery + vartime_double_base)
    {
        use curve25519_dalek_ng::constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT};
        use curve25519_dalek_ng::edwards::{CompressedEdwardsY, EdwardsPoint};
        use curve25519_dalek_ng::montgomery::MontgomeryPoint;
        use curve25519_dalek_ng::ristretto::CompressedRistretto;
        use curve25519_dalek_ng::scalar::Scalar;
        let a = Scalar::from_bytes_mod_order([0x11u8; 32]);
        let b = Scalar::from_bytes_mod_order([0x22u8; 32]);
        let p = &a * &ED25519_BASEPOINT_POINT;
        let q = EdwardsPoint::vartime_double_scalar_mul_basepoint(&a, &p, &b);
        let c = q.compress();
        let _ = core::hint::black_box((c.decompress(), CompressedEdwardsY::from_slice(&[0x33u8; 32]).decompress()));
        let r = &a * &RISTRETTO_BASEPOINT_POINT;
        let rc = r.compress();
        let _ = core::hint::black_box((rc.decompress(), CompressedRistretto::from_slice(&[0x44u8; 32]).decompress()));
        let m = MontgomeryPoint([0x55u8; 32]) * a;
        let _ = core::hint::black_box((m, a.invert(), a * b + a));
    }

    // ethabi 18.0.0 full ParamType encode/decode + Contract JSON parse
    {
        let tokens = vec![
            ethabi::Token::Address(ethabi::Address::from([0x11u8; 20])),
            ethabi::Token::Uint(ethabi::Uint::from(123456789u64)),
            ethabi::Token::Int(ethabi::Int::from(999u64)),
            ethabi::Token::Bool(true),
            ethabi::Token::String(arg.to_string()),
            ethabi::Token::Bytes(arg.as_bytes().to_vec()),
            ethabi::Token::FixedBytes(vec![0xaa; 32]),
            ethabi::Token::Array(vec![ethabi::Token::Uint(ethabi::Uint::from(1u64))]),
            ethabi::Token::Tuple(vec![ethabi::Token::Bool(false), ethabi::Token::String("x".into())]),
        ];
        let enc = ethabi::encode(&tokens);
        let types = vec![
            ethabi::ParamType::Address,
            ethabi::ParamType::Uint(256),
            ethabi::ParamType::Int(256),
            ethabi::ParamType::Bool,
            ethabi::ParamType::String,
            ethabi::ParamType::Bytes,
            ethabi::ParamType::FixedBytes(32),
            ethabi::ParamType::Array(Box::new(ethabi::ParamType::Uint(256))),
            ethabi::ParamType::Tuple(vec![ethabi::ParamType::Bool, ethabi::ParamType::String]),
        ];
        let _ = core::hint::black_box(ethabi::decode(&types, &enc));
        let _ = core::hint::black_box(ethabi::Contract::load(arg.as_bytes()));
    }

    // ethers-core 2.0.14 (Signature, Transaction, Block, EIP-712, RLP, utils)
    {
        let _ = core::hint::black_box(ethers_core::utils::keccak256(arg.as_bytes()));
        let _ = core::hint::black_box(ethers_core::utils::to_checksum(&ethers_core::types::Address::from([0xab; 20]), None));
        let _ = core::hint::black_box(ethers_core::utils::parse_ether(arg));
        let _ = core::hint::black_box(ethers_core::utils::format_ether(ethers_core::types::U256::from(1_000_000_000_000_000_000u128)));
        let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Transaction>(arg));
        let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::TransactionReceipt>(arg));
        let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Block<ethers_core::types::H256>>(arg));
        let _ = core::hint::black_box(arg.parse::<ethers_core::types::Signature>());
        let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::transaction::eip712::TypedData>(arg));
    }

    // rust_decimal 1.36.0 (maths + parse + round + serde)
    {
        use rust_decimal::MathematicalOps;
        let d1: rust_decimal::Decimal = arg.parse().unwrap_or(rust_decimal::Decimal::new(123456, 4));
        let d2 = rust_decimal::Decimal::new(789012, 5);
        let _ = core::hint::black_box((
            d1.checked_mul(d2),
            d1.checked_div(d2),
            d1.sqrt(),
            d1.powi(3),
            d1.exp(),
            d1.ln(),
            d1.round_dp(2),
            d1.normalize(),
            serde_json::to_string(&d1),
            serde_json::from_str::<rust_decimal::Decimal>(arg),
        ));
    }

    // primitive-types 0.12.2 + impl-serde 0.4.0
    {
        let u = primitive_types::U256::from_dec_str(arg).unwrap_or(primitive_types::U256::from(999999u64));
        let h = primitive_types::H256::from([0x77u8; 32]);
        let a = primitive_types::H160::from([0x88u8; 20]);
        let _ = core::hint::black_box((
            serde_json::to_string(&(u, h, a)),
            serde_json::from_str::<(primitive_types::U256, primitive_types::H256, primitive_types::H160)>(arg),
            u.checked_mul(u),
            u.div_mod(primitive_types::U256::from(13u64)),
            u.integer_sqrt(),
        ));
    }

    // secp256k1 0.29 & 0.30 (sign_ecdsa_recoverable, recover, verify, schnorr, ecdh)
    {
        let secp = secp256k1_29::Secp256k1::new();
        let sk = secp256k1_29::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let pk = secp256k1_29::PublicKey::from_secret_key(&secp, &sk);
        let msg = secp256k1_29::Message::from_digest([0x22u8; 32]);
        let rsig = secp.sign_ecdsa_recoverable(&msg, &sk);
        let _ = core::hint::black_box(secp.recover_ecdsa(&msg, &rsig));
        let sig = secp.sign_ecdsa(&msg, &sk);
        let _ = core::hint::black_box(secp.verify_ecdsa(&msg, &sig, &pk));
        let kp = secp256k1_29::Keypair::from_secret_key(&secp, &sk);
        let ssig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let _ = core::hint::black_box(secp.verify_schnorr(&ssig, &msg, &kp.x_only_public_key().0));
    }
    {
        let secp = secp256k1_30::Secp256k1::new();
        let sk = secp256k1_30::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let pk = secp256k1_30::PublicKey::from_secret_key(&secp, &sk);
        let msg = secp256k1_30::Message::from_digest([0x22u8; 32]);
        let rsig = secp.sign_ecdsa_recoverable(&msg, &sk);
        let _ = core::hint::black_box(secp.recover_ecdsa(&msg, &rsig));
        let sig = secp.sign_ecdsa(&msg, &sk);
        let _ = core::hint::black_box(secp.verify_ecdsa(&msg, &sig, &pk));
    }

    // openssl 0.10.82 (SslConnector, SslAcceptor, X509, PKey, Hash, Cipher)
    {
        let _ = core::hint::black_box(openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()));
        let _ = core::hint::black_box(openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()));
        let _ = core::hint::black_box(openssl::x509::X509::from_pem(arg.as_bytes()));
        let _ = core::hint::black_box(openssl::x509::X509::from_der(arg.as_bytes()));
        let _ = core::hint::black_box(openssl::pkey::PKey::private_key_from_pem(arg.as_bytes()));
        let _ = core::hint::black_box(openssl::hash::hash(openssl::hash::MessageDigest::sha256(), arg.as_bytes()));
        let _ = core::hint::black_box(openssl::symm::encrypt(openssl::symm::Cipher::aes_256_gcm(), &[0u8; 32], Some(&[0u8; 12]), arg.as_bytes()));
    }

    // sha2 0.11.1, ripemd 0.2.0, const-hex 1.14.1, base64 0.22.1, bs58, tiny-keccak, aurora-engine-modexp, lz4_flex 0.14.0, bitvec 1.1.1
    {
        use sha2_11::Digest as D11;
        let _ = core::hint::black_box((sha2_11::Sha256::digest(arg.as_bytes()), sha2_11::Sha512::digest(arg.as_bytes())));
        use ripemd_02::Digest as DR;
        let _ = core::hint::black_box(ripemd_02::Ripemd160::digest(arg.as_bytes()));
        let _ = core::hint::black_box((const_hex::encode(arg.as_bytes()), const_hex::decode(arg.as_bytes())));
        use base64_22::Engine;
        let _ = core::hint::black_box((
            base64_22::engine::general_purpose::STANDARD.encode(arg.as_bytes()),
            base64_22::engine::general_purpose::STANDARD.decode(arg.as_bytes()),
        ));
        let _ = core::hint::black_box((bs58::encode(arg.as_bytes()).into_string(), bs58::decode(arg.as_bytes()).into_vec()));
        use tiny_keccak::Hasher;
        let mut tk = tiny_keccak::Keccak::v256();
        tk.update(arg.as_bytes());
        let mut out = [0u8; 32];
        tk.finalize(&mut out);
        let _ = core::hint::black_box(out);
        let _ = core::hint::black_box(aurora_engine_modexp::modexp(arg.as_bytes(), b"\x03", b"\x00\x00\x00\x00\x00\x00\x00\x11"));
        let comp = lz4_flex::compress_prepend_size(arg.as_bytes());
        let _ = core::hint::black_box(lz4_flex::decompress_size_prepended(&comp));
        let mut bv = bitvec::vec::BitVec::<u8, bitvec::order::Lsb0>::repeat(false, 128);
        bv.set(5, true);
        let _ = core::hint::black_box(bv.count_ones());
    }

    // serde_yaml, serde_path_to_error, rmp-serde 1.3.1, anyhow 1.0.97
    {
        let _ = core::hint::black_box(serde_yaml::from_str::<serde_yaml::Value>(arg));
        let mut jd = serde_json::Deserializer::from_str(arg);
        let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, serde_json::Value>(&mut jd));
        let _ = core::hint::black_box(rmp_serde::from_slice::<serde_json::Value>(arg.as_bytes()));
        let _ = core::hint::black_box(anyhow::anyhow!("err: {arg}"));
    }

    // clap 2.34.0 full parser/help/usage/validator + log4rs 1.3.0 + sysinfo 0.29.11
    {
        let app = clap::App::new("hl-node")
            .version("1.0")
            .about("node")
            .arg(clap::Arg::with_name("chain").long("chain").takes_value(true).possible_values(&["Mainnet", "Testnet"]))
            .arg(clap::Arg::with_name("verbose").short("v").multiple(true))
            .subcommand(clap::SubCommand::with_name("run-validator").arg(clap::Arg::with_name("config").required(true)));
        let _ = core::hint::black_box(app.get_matches_from_safe(["hl-node", "--chain", arg, "-vv"]));
        let _ = core::hint::black_box(log4rs::config::load_config_file(arg, log4rs::config::Deserializers::default()));
        use sysinfo::{NetworksExt, ProcessExt, SystemExt};
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        let _ = core::hint::black_box((
            sys.total_memory(),
            sys.used_memory(),
            sys.cpus().len(),
            sys.disks().len(),
            sys.networks().iter().count(),
            sys.processes().values().next().map(|p| (p.name().to_string(), p.memory(), p.cpu_usage())),
        ));
    }

    // jsonrpsee-core 0.26.1 + tokio 1.54.1 + axum 0.8.9
    {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let s = arg.to_string();
        rt.block_on(async move {
            let mut module = jsonrpsee_core::server::RpcModule::new(());
            let _ = module.register_method("eth_chainId", |_, _, _| "0x3e7");
            let _ = core::hint::black_box(module.raw_json_request(&s, 1).await);
            let app: axum::Router = axum::Router::new()
                .route("/info", axum::routing::post(|axum::Json(v): axum::Json<serde_json::Value>| async move { axum::Json(v) }))
                .route("/ws", axum::routing::get(|ws: axum::extract::ws::WebSocketUpgrade| async move { ws.on_upgrade(|_| async {}) }));
            let _ = core::hint::black_box(app);
        });
    }
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "test".to_string());
    if arg == "__never__" {
        touch_revm43_alloy25(&arg);
        touch_deep_crypto_misc(&arg);
    }
}
