use clap4 as clap;
use std::net::SocketAddr;
use std::time::Duration;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(clap::Parser, Debug)]
#[command(name = "hl", version = "1.0", about = "hl")]
struct Cli4 {
    #[arg(short, long, env = "HL_MODE")]
    mode: Option<String>,
    #[arg(short, long, default_value_t = 1)]
    count: u64,
    #[arg(long)]
    verbose: bool,
}

#[inline(never)]
fn touch_revm_deep(arg: &str) {
    use revm::{ExecuteCommitEvm, ExecuteEvm, InspectEvm, MainBuilder, MainContext};
    let mut db = revm::database::InMemoryDB::default();
    let code = revm::state::Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(arg.as_bytes()));
    let _ = core::hint::black_box(revm::state::Bytecode::new_legacy(revm::primitives::Bytes::copy_from_slice(arg.as_bytes())));
    let target = revm::primitives::Address::from([0x11u8; 20]);
    db.insert_account_info(
        target,
        revm::state::AccountInfo {
            balance: revm::primitives::U256::from(1_000_000u64),
            nonce: 1,
            code_hash: code.hash_slow(),
            code: Some(code),
            account_id: None,
        },
    );
    let ctx = revm::Context::mainnet().with_db(db);
    let mut evm = ctx.build_mainnet_with_inspector(revm::inspector::NoOpInspector {});
    let tx_call = revm::context::TxEnv::builder()
        .caller(revm::primitives::Address::ZERO)
        .kind(revm::primitives::TxKind::Call(target))
        .gas_limit(1_000_000)
        .gas_price(10)
        .data(revm::primitives::Bytes::copy_from_slice(arg.as_bytes()))
        .build_fill();
    let _ = core::hint::black_box(evm.inspect_tx(tx_call.clone()));
    let _ = core::hint::black_box(evm.transact_commit(tx_call));
    let tx_create = revm::context::TxEnv::builder()
        .caller(revm::primitives::Address::ZERO)
        .kind(revm::primitives::TxKind::Create)
        .gas_limit(1_000_000)
        .data(revm::primitives::Bytes::copy_from_slice(arg.as_bytes()))
        .build_fill();
    let _ = core::hint::black_box(evm.transact(tx_create));

    let pre = revm::precompile::Precompiles::prague();
    for addr in pre.addresses() {
        if let Some(f) = pre.get(addr) {
            let _ = core::hint::black_box(f.execute(arg.as_bytes(), 1_000_000, 0));
        }
    }
    let pre_c = revm::precompile::Precompiles::cancun();
    for addr in pre_c.addresses() {
        if let Some(f) = pre_c.get(addr) {
            let _ = core::hint::black_box(f.execute(arg.as_bytes(), 1_000_000, 0));
        }
    }
}

#[inline(never)]
fn touch_alloy_ark_deep(arg: &str) {
    use alloy_rlp::{Decodable, Encodable};
    use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
    use ark_ff::Field;
    // Deep alloy-trie + nybbles
    let mut hb = alloy_trie::HashBuilder::default().with_proof_retainer(alloy_trie::proof::ProofRetainer::from_iter([
        alloy_trie::Nibbles::unpack(arg.as_bytes()),
    ]));
    hb.add_leaf(alloy_trie::Nibbles::unpack(b"aa"), b"v1");
    hb.add_leaf(alloy_trie::Nibbles::unpack(b"ab"), b"v2");
    hb.add_branch(alloy_trie::Nibbles::unpack(b"ac"), alloy_primitives::B256::ZERO, false);
    let root = hb.root();
    let proofs = hb.take_proof_nodes();
    let _ = core::hint::black_box((root, proofs));
    let mut nib = alloy_trie::Nibbles::unpack(arg.as_bytes());
    let _ = core::hint::black_box((nib.pack(), nib.common_prefix_length(&alloy_trie::Nibbles::unpack(b"abc")), nib.pop()));

    // Deep alloy-consensus + alloy-rlp + alloy-rpc-types-eth
    let mut slice = arg.as_bytes();
    if let Ok(tx) = alloy_consensus::TxEnvelope::decode(&mut slice) {
        let mut out = Vec::new();
        tx.encode(&mut out);
        let _ = core::hint::black_box((tx.tx_hash(), out));
    }
    let mut hslice = arg.as_bytes();
    if let Ok(hdr) = alloy_consensus::Header::decode(&mut hslice) {
        let mut out = Vec::new();
        hdr.encode(&mut out);
        let _ = core::hint::black_box((hdr.hash_slow(), out));
    }
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionRequest>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Filter>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Log>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::TxEnvelope>(arg));

    // Deep ark-bn254 / ark-ec / ark-ff
    let g1 = ark_bn254::G1Affine::generator();
    let g2 = ark_bn254::G2Affine::generator();
    let fr = ark_bn254::Fr::from(arg.len() as u64 + 7);
    let _ = core::hint::black_box((
        ark_bn254::G1Projective::msm(&[g1, g1], &[fr, fr]),
        ark_bn254::G2Projective::msm(&[g2, g2], &[fr, fr]),
        ark_bn254::Bn254::multi_pairing([g1], [g2]),
        fr.inverse(),
    ));
    let _ = core::hint::black_box(aurora_engine_modexp::modexp(arg.as_bytes(), &[3], &[17]));
    let _ = core::hint::black_box(<Cli4 as clap::Parser>::try_parse_from(["hl", "--mode", arg, "--help"]));
}

#[inline(never)]
fn touch_hyper1416_h204_tokio145(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        // Deep hyper 0.14.16 (exact hyper-fork base!) HTTP/1 + HTTP/2 client & server
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build_http();
        if let Ok(req) = hyper::Request::post(&s).body(hyper::Body::from(s.clone())) {
            if let Ok(resp) = client.request(req).await {
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            let make_svc = hyper::service::make_service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(hyper::service::service_fn(|req: hyper::Request<hyper::Body>| async move {
                    let b = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(b)))
                }))
            });
            let _ = hyper::Server::bind(&addr).http2_adaptive_window(true).serve(make_svc).await;
        }
        // Deep h2 0.4.11 client + server + streams
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok((send_req, mut conn)) = h2_04::client::Builder::new()
                .initial_window_size(65536)
                .handshake::<_, bytes::Bytes>(stream)
                .await
            {
                if let Some(mut pp) = conn.ping_pong() {
                    let _ = pp.send_ping(h2_04::Ping::opaque());
                }
                tokio::spawn(async move { let _ = conn.await; });
                if let Ok(mut ready) = send_req.ready().await {
                    let req = http_1::Request::builder().uri("https://example.com/").body(()).unwrap();
                    if let Ok((rf, mut ss)) = ready.send_request(req, false) {
                        let _ = ss.send_data(bytes::Bytes::from_static(b"hi"), true);
                        if let Ok(resp) = rf.await {
                            let mut body = resp.into_body();
                            while let Some(Ok(c)) = body.data().await {
                                let _ = body.flow_control().release_capacity(c.len());
                            }
                        }
                    }
                }
            }
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok(mut conn) = h2_04::server::Builder::new().handshake::<_, bytes::Bytes>(stream).await {
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let _ = req.into_body().data().await;
                    let resp = http_1::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            }
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
                let app = axum_08::Router::new()
                    .route("/x", axum_08::routing::post(|axum_08::Json(v): axum_08::Json<serde_json::Value>| async move { axum_08::Json(v) }))
                    .route("/ws", axum_08::routing::get(|ws: axum_08::extract::WebSocketUpgrade| async move { ws.on_upgrade(|_| async {}) }));
                let _ = axum_08::serve(listener, app).await;
            }
        }
    });
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_revm_deep(&arg);
        touch_alloy_ark_deep(&arg);
        touch_hyper1416_h204_tokio145(&arg);
    }
}
