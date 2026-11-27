use clap4 as clap;
use tikv_jemallocator::Jemalloc;
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(clap::Parser, Debug)]
struct Cli4 {
    #[arg(short, long, env = "HL_MODE")]
    mode: Option<String>,
    #[arg(short, long, default_value_t = 1)]
    count: u64,
    #[arg(long)]
    verbose: bool,
}

#[inline(never)]
fn touch_revm_alloy_ark(arg: &str) {
    use ark_ec::AffineRepr;
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use revm::MainContext;
    let ctx = revm::Context::mainnet().with_db(revm::database::InMemoryDB::default());
    let mut evm = revm::MainBuilder::build_mainnet(ctx);
    let tx = revm::context::TxEnv::builder()
        .caller(revm::primitives::Address::ZERO)
        .gas_limit(100_000)
        .data(revm::primitives::Bytes::copy_from_slice(arg.as_bytes()))
        .build_fill();
    let _ = core::hint::black_box(revm::ExecuteEvm::transact(&mut evm, tx));

    // Exercise all revm precompiles directly too
    let pre = revm::precompile::Precompiles::prague();
    for addr in pre.addresses() {
        if let Some(f) = pre.get(addr) {
            let _ = core::hint::black_box(f.execute(arg.as_bytes(), 100_000, 0));
        }
    }

    let g1 = ark_bn254::G1Affine::generator();
    let g2 = ark_bn254::G2Affine::generator();
    let fr = ark_bn254::Fr::from(arg.len() as u64 + 1);
    let _ = core::hint::black_box((g1 * fr, g2 * fr, fr.inverse()));
    let _ = core::hint::black_box(ark_bn254::Bn254::multi_pairing([g1], [g2]));

    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionRequest>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Filter>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Log>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxEnvelope>(arg));
    let _ = core::hint::black_box(alloy_primitives::Address::parse_checksummed(arg, None));
    let _ = core::hint::black_box(alloy_primitives::keccak256(arg.as_bytes()));
    let mut hb = alloy_trie::HashBuilder::default();
    hb.add_leaf(alloy_trie::Nibbles::unpack(arg.as_bytes()), arg.as_bytes());
    let _ = core::hint::black_box(hb.root());
    let mut rlp_out = Vec::new();
    alloy_rlp::Encodable::encode(&arg.as_bytes(), &mut rlp_out);
    let _ = core::hint::black_box(rlp_out);
    let _ = core::hint::black_box(aurora_engine_modexp::modexp(arg.as_bytes(), &[3], &[17]));
}

#[inline(never)]
fn touch_crypto_misc(arg: &str) {
    use std::io::{Read, Write};
    let secp29 = secp256k1_29::Secp256k1::new();
    if let Ok(msg) = secp256k1_29::Message::from_digest_slice(arg.as_bytes()) {
        if let Ok(sk) = secp256k1_29::SecretKey::from_slice(arg.as_bytes()) {
            let sig = secp29.sign_ecdsa_recoverable(&msg, &sk);
            let _ = core::hint::black_box(secp29.recover_ecdsa(&msg, &sig));
        }
    }
    let secp30 = secp256k1_30::Secp256k1::new();
    let msg30 = secp256k1_30::Message::from_digest([1u8; 32]);
    let sk30 = secp256k1_30::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let sig30 = secp30.sign_ecdsa_recoverable(&msg30, &sk30);
    let _ = core::hint::black_box(secp30.recover_ecdsa(&msg30, &sig30));
    let _ = core::hint::black_box(p256::ecdsa::SigningKey::from_slice(arg.as_bytes()));
    let _ = core::hint::black_box(p256::ecdsa::VerifyingKey::from_sec1_bytes(arg.as_bytes()));
    let _ = core::hint::black_box(bincode1::serialize(&vec![arg.to_string()]));
    let _ = core::hint::black_box(bincode1::deserialize::<Vec<String>>(arg.as_bytes()));
    let _ = core::hint::black_box(serde_yaml::from_str::<serde_yaml::Value>(arg));
    let _ = core::hint::black_box(regex::Regex::new(arg));
    let _ = core::hint::black_box(chrono::DateTime::parse_from_rfc3339(arg));
    let _ = core::hint::black_box(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.fZ").to_string());
    let _ = core::hint::black_box(<Cli4 as clap::Parser>::try_parse_from(["hl", "--mode", arg]));
    let mut m: hashbrown_15::HashMap<String, u64> = hashbrown_15::HashMap::new();
    m.insert(arg.to_string(), 1);
    let mut im: indexmap::IndexMap<String, u64> = indexmap::IndexMap::new();
    im.insert(arg.to_string(), 1);
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(arg.as_bytes());
    let gz = enc.finish().unwrap_or_default();
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut out = String::new();
    let _ = dec.read_to_string(&mut out);
    let _ = core::hint::black_box((m, im, out));
}

#[inline(never)]
fn touch_net2(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build_http();
        if let Ok(uri) = s.parse::<hyper::Uri>() {
            let _ = core::hint::black_box(client.get(uri).await);
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            let _ = core::hint::black_box(h2_04::client::handshake(stream).await);
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            let _ = core::hint::black_box(h2_04::server::handshake(stream).await);
        }
        if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
            if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
                let app = axum_08::Router::new()
                    .route("/x", axum_08::routing::get(|| async { "ok" }))
                    .route("/ws", axum_08::routing::get(|ws: axum_08::extract::WebSocketUpgrade| async move { ws.on_upgrade(|_| async {}) }));
                let _ = axum_08::serve(listener, app).await;
            }
        }
        let _ = core::hint::black_box(tokio_tungstenite::connect_async(&s).await);
    });
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_revm_alloy_ark(&arg);
        touch_crypto_misc(&arg);
        touch_net2(&arg);
    }
}
