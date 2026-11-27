use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_std(arg: &str) {
    let bt = std::backtrace::Backtrace::force_capture();
    let _ = core::hint::black_box(format!("{bt}"));
    if let Ok(mut f) = std::fs::OpenOptions::new().read(true).open(arg) {
        let mut s = String::new();
        let _ = f.read_to_string(&mut s);
        let mut r = BufReader::new(f);
        let mut line = String::new();
        let _ = r.read_line(&mut line);
        let _ = core::hint::black_box((s, line));
    }
    if let Ok(f) = std::fs::File::create(arg) {
        let mut w = BufWriter::new(f);
        let _ = w.write_all(arg.as_bytes());
        let _ = w.flush();
    }
    let _ = core::hint::black_box(std::fs::read_dir(arg));
    let _ = core::hint::black_box(std::fs::metadata(arg));
    let _ = core::hint::black_box(std::fs::canonicalize(arg));
    let _ = core::hint::black_box(std::fs::create_dir_all(arg));
    let _ = core::hint::black_box(std::fs::remove_file(arg));
    let _ = core::hint::black_box(std::env::var(arg));
    let _ = core::hint::black_box(std::env::current_dir());
    let _ = core::hint::black_box(std::env::current_exe());
    let _ = core::hint::black_box(std::process::Command::new(arg).arg("--x").output());
    if let Ok(l) = TcpListener::bind(arg) {
        let _ = core::hint::black_box(l.accept());
    }
    if let Ok(mut s) = TcpStream::connect(arg) {
        let mut b = [0u8; 16];
        let _ = s.read(&mut b);
        let _ = s.write(&b);
    }
    if let Ok(u) = UdpSocket::bind(arg) {
        let mut b = [0u8; 16];
        let _ = u.recv_from(&mut b);
    }
    let m = Arc::new((Mutex::new(0u64), Condvar::new()));
    let rw = Arc::new(RwLock::new(Vec::<String>::new()));
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let m2 = m.clone();
    let h = std::thread::spawn(move || {
        let mut g = m2.0.lock().unwrap();
        *g += 1;
        m2.1.notify_all();
    });
    let _ = tx.send(arg.to_string());
    let _ = core::hint::black_box(rx.recv());
    let _ = rw.write().unwrap().push(arg.to_string());
    let _ = h.join();
    let mut hm = HashMap::<String, u64>::new();
    hm.insert(arg.to_string(), 1);
    let mut bm = BTreeMap::<String, u64>::new();
    bm.insert(arg.to_string(), 1);
    let mut vd = VecDeque::<u64>::new();
    vd.push_back(1);
    let mut bh = BinaryHeap::<u64>::new();
    bh.push(1);
    let _ = core::hint::black_box((hm, bm, vd, bh, std::time::SystemTime::now(), std::time::Instant::now()));
    let _ = core::hint::black_box(std::fs::copy(arg, arg));
    let _ = core::hint::black_box(std::fs::rename(arg, arg));
    let _ = core::hint::black_box(std::fs::read_link(arg));
    let _ = core::hint::black_box(std::fs::symlink_metadata(arg));
    let _ = core::hint::black_box(std::fs::hard_link(arg, arg));
    let _ = core::hint::black_box(arg.parse::<std::net::IpAddr>());
    let _ = core::hint::black_box(arg.parse::<std::net::SocketAddr>());
    let _ = core::hint::black_box(arg.parse::<f64>());
    let _ = core::hint::black_box(arg.parse::<i128>());
    let _ = core::hint::black_box(std::panic::catch_unwind(|| core::hint::black_box(arg.len())));
    let _ = core::hint::black_box(std::env::vars().collect::<Vec<_>>());
    let _ = core::hint::black_box(std::env::args_os().collect::<Vec<_>>());
    let _ = core::hint::black_box(std::thread::Builder::new().name(arg.to_string()).spawn(|| ()));
    let _ = core::hint::black_box(std::io::Cursor::new(arg.as_bytes()).lines().count());
    let _ = core::hint::black_box(std::path::PathBuf::from(arg).components().count());
}

#[inline(never)]
fn touch_clap() {
    let mut app = clap::App::new("hl-node")
        .version("1.0")
        .about("node")
        .arg(clap::Arg::with_name("a").short("a").long("alpha").takes_value(true).multiple(true).conflicts_with("b").requires("c"))
        .arg(clap::Arg::with_name("b").short("b").long("beta").takes_value(true).possible_values(&["x", "y"]))
        .arg(clap::Arg::with_name("c").short("c").long("gamma").default_value("1"))
        .subcommand(clap::SubCommand::with_name("run").arg(clap::Arg::with_name("d").required(true)));
    let mut out = Vec::new();
    let _ = app.write_help(&mut out);
    let _ = app.write_long_help(&mut out);
    app.gen_completions_to("hl-node", clap::Shell::Bash, &mut out);
    let m = app.get_matches_from_safe(["hl-node", "--alpha", "1"]);
    let _ = core::hint::black_box((out, m));
}

#[inline(never)]
fn touch_sysinfo_log4rs_chrono(arg: &str) {
    use sysinfo::SystemExt;
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    sys.refresh_processes();
    sys.refresh_cpu();
    sys.refresh_memory();
    sys.refresh_disks_list();
    sys.refresh_networks_list();
    sys.refresh_components_list();
    sys.refresh_users_list();
    let _ = core::hint::black_box((sys.cpus().len(), sys.disks().len(), sys.networks(), sys.processes().len(), sys.components().len(), sys.users().len()));
    let _ = core::hint::black_box(log4rs::init_file(arg, Default::default()));
    let _ = core::hint::black_box(serde_json::from_str::<log4rs::config::RawConfig>(arg));
    let _ = core::hint::black_box(chrono::DateTime::parse_from_rfc3339(arg));
    let _ = core::hint::black_box(chrono::DateTime::parse_from_rfc2822(arg));
    let _ = core::hint::black_box(chrono::DateTime::parse_from_str(arg, "%+"));
    let _ = core::hint::black_box(chrono::NaiveDateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S"));
    let _ = core::hint::black_box(chrono::NaiveDate::parse_from_str(arg, "%Y-%m-%d"));
    let _ = core::hint::black_box(chrono::NaiveTime::parse_from_str(arg, "%H:%M:%S"));
    let _ = core::hint::black_box(chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.f %z").to_string());
    let _ = core::hint::black_box(chrono::Utc::now().to_rfc3339());
    if let Ok(u) = url::Url::parse(arg) {
        let _ = core::hint::black_box((u.join(arg), u.query_pairs().count(), u.path_segments().map(|s| s.count())));
    }
    let _ = core::hint::black_box(idna::domain_to_ascii(arg));
}

#[inline(never)]
fn touch_async_net(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        let https = hyper_tls::HttpsConnector::new();
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().http2_only(false).build(https);
        if let Ok(uri) = s.parse::<hyper::Uri>() {
            let _ = core::hint::black_box(client.get(uri).await);
        }
        if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
            let app = axum::Router::new()
                .route("/info", axum::routing::post(|axum::Json(v): axum::Json<serde_json::Value>| async move { axum::Json(v) }))
                .route("/ws", axum::routing::get(|ws: axum::extract::ws::WebSocketUpgrade| async move { ws.on_upgrade(|_| async {}) }));
            let _ = axum::Server::bind(&addr).serve(app.into_make_service()).await;
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            let _ = core::hint::black_box(h2::client::handshake(stream).await);
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            let _ = core::hint::black_box(h2::server::handshake(stream).await);
        }
        let _ = core::hint::black_box(tokio::fs::read(&s).await);
        let _ = core::hint::black_box(tokio::process::Command::new(&s).output().await);
        let _ = core::hint::black_box(tokio::signal::ctrl_c().await);
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    });
}

#[inline(never)]
fn touch_crypto_ser_rayon(arg: &str) {
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
    let sum: usize = pool.install(|| (0..100usize).into_par_iter().map(|x| x * 2).sum());
    let _ = core::hint::black_box(sum);
    let _ = core::hint::black_box(serde_json::from_str::<serde_json::Value>(arg));
    let _ = core::hint::black_box(serde_json::to_string_pretty(&serde_json::json!({"a": [1, 2.5, arg]})));
    let _ = core::hint::black_box(rmp_serde::from_slice::<serde_json::Value>(arg.as_bytes()));
    let _ = core::hint::black_box(rmp_serde::to_vec_named(&serde_json::json!({"a": arg})));
    let _ = core::hint::black_box(lz4_flex::block::compress_prepend_size(arg.as_bytes()));
    let _ = core::hint::black_box(lz4_flex::block::decompress_size_prepended(arg.as_bytes()));
    let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
    let _ = enc.write_all(arg.as_bytes());
    let framed = enc.finish().unwrap_or_default();
    let mut dec = lz4_flex::frame::FrameDecoder::new(&framed[..]);
    let mut dec_out = Vec::new();
    let _ = dec.read_to_end(&mut dec_out);
    let _ = core::hint::black_box(dec_out);
    let _ = core::hint::black_box(blake3::hash(arg.as_bytes()));
    let _ = core::hint::black_box(rust_decimal::Decimal::from_str_exact(arg));
    let _ = core::hint::black_box(rust_decimal::Decimal::from_scientific(arg));
    let _ = core::hint::black_box(bincode::encode_to_vec(vec![arg.to_string()], bincode::config::standard()));
    let _ = core::hint::black_box(bincode::decode_from_slice::<Vec<String>, _>(arg.as_bytes(), bincode::config::standard()));
    let _ = core::hint::black_box(bincode::decode_from_slice::<Vec<String>, _>(arg.as_bytes(), bincode::config::legacy()));
    let _ = core::hint::black_box(k256::ecdsa::SigningKey::from_slice(arg.as_bytes()));
    let _ = core::hint::black_box(k256::ecdsa::VerifyingKey::from_sec1_bytes(arg.as_bytes()));
    let _ = core::hint::black_box(k256::SecretKey::from_slice(arg.as_bytes()));
    let _ = core::hint::black_box(k256::PublicKey::from_sec1_bytes(arg.as_bytes()));
    let _ = core::hint::black_box(ethabi::Contract::load(arg.as_bytes()));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Transaction>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Block<ethers_core::types::H256>>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::TransactionReceipt>(arg));
    let _ = core::hint::black_box(<ethers_core::types::Signature as std::str::FromStr>::from_str(arg));
    let _ = core::hint::black_box(openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()));
    let _ = core::hint::black_box(openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()));
    let _ = core::hint::black_box(openssl::x509::X509::from_pem(arg.as_bytes()));
    let _ = core::hint::black_box(openssl::pkey::PKey::private_key_from_pem(arg.as_bytes()));
    let _ = core::hint::black_box(native_tls::TlsConnector::builder().build());
    let _ = core::hint::black_box(anyhow::anyhow!("err: {arg}"));
    let mut lru = lru::LruCache::new(std::num::NonZeroUsize::new(16).unwrap());
    lru.put(arg.to_string(), 1u64);
    let _ = core::hint::black_box(lru.get(arg));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_std(&arg);
        touch_clap();
        touch_sysinfo_log4rs_chrono(&arg);
        touch_async_net(&arg);
        touch_crypto_ser_rayon(&arg);
    }
}
