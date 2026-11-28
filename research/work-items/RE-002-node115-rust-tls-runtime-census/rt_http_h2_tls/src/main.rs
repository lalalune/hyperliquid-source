use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hint::black_box;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

async fn exercise_tokio_deep() {
    // Channels: mpsc, broadcast, watch, oneshot
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let _ = tx.send(vec![1u8; 16]).await;
    let _ = black_box(rx.recv().await);
    let (utx, mut urx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = utx.send("hi".into());
    let _ = black_box(urx.recv().await);
    let (btx, mut brx) = tokio::sync::broadcast::channel::<u64>(16);
    let _ = btx.send(42);
    let _ = black_box(brx.recv().await);
    let (wtx, mut wrx) = tokio::sync::watch::channel(0u64);
    let _ = wtx.send(1);
    let _ = black_box(wrx.changed().await);
    let (otx, orx) = tokio::sync::oneshot::channel::<u64>();
    let _ = otx.send(7);
    let _ = black_box(orx.await);

    // Sync primitives: Mutex, RwLock, Semaphore, Notify, Barrier, OnceCell
    let mu = Arc::new(tokio::sync::Mutex::new(HashMap::<String, u64>::new()));
    mu.lock().await.insert("k".into(), 1);
    let rw = Arc::new(tokio::sync::RwLock::new(BTreeMap::<u64, String>::new()));
    rw.write().await.insert(1, "v".into());
    let _ = black_box(rw.read().await.get(&1).cloned());
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let _p = sem.acquire_many(2).await;
    let notify = Arc::new(tokio::sync::Notify::new());
    notify.notify_one();
    notify.notified().await;

    // Task: JoinSet, spawn, spawn_blocking, yield_now, LocalSet
    let mut js = tokio::task::JoinSet::new();
    js.spawn(async { tokio::task::yield_now().await; black_box(1u64) });
    js.spawn_blocking(|| black_box(2u64));
    while let Some(res) = js.join_next().await {
        let _ = black_box(res);
    }
    let local = tokio::task::LocalSet::new();
    local.run_until(async {
        let h = tokio::task::spawn_local(async { black_box(3u64) });
        let _ = black_box(h.await);
    }).await;

    // Time: sleep, timeout, interval
    let _ = tokio::time::timeout(Duration::from_millis(5), tokio::time::sleep(Duration::from_millis(1))).await;
    let mut iv = tokio::time::interval(Duration::from_millis(1));
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    iv.tick().await;

    // Net & IO: TcpListener, TcpStream, UdpSocket, duplex, copy_bidirectional, framed
    if let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await {
        let addr = listener.local_addr().unwrap();
        let c = tokio::spawn(async move {
            if let Ok(mut s) = tokio::net::TcpStream::connect(addr).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let _ = s.write_all(b"ping").await;
                let mut buf = [0u8; 16];
                let _ = s.read(&mut buf).await;
                black_box(buf);
            }
        });
        if let Ok((mut srv, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 16];
            let _ = srv.read(&mut buf).await;
            let _ = srv.write_all(b"pong").await;
        }
        let _ = c.await;
    }
    if let Ok(udp) = tokio::net::UdpSocket::bind("127.0.0.1:0").await {
        let addr = udp.local_addr().unwrap();
        let _ = udp.send_to(b"hello", addr).await;
        let mut buf = [0u8; 16];
        let _ = black_box(udp.recv_from(&mut buf).await);
    }
    let (mut a, mut b) = tokio::io::duplex(256);
    let (mut c, mut d) = tokio::io::duplex(256);
    if black_box(false) {
        let _ = tokio::io::copy_bidirectional(&mut a, &mut c).await;
        drop((b, d));
    }
    let _ = black_box(tokio_util::codec::LinesCodec::new());
    let _ = black_box(tokio_util::codec::LengthDelimitedCodec::new());
}

async fn exercise_http_h2_axum_ws() {
    // Never execute blocking servers, just instantiate and drive state machines
    if black_box(false) {
        // h2 0.3 client + server
        let (a, b) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            if let Ok(mut conn) = h2::server::handshake(a).await {
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let _ = black_box(req.uri());
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            }
        });
        if let Ok((mut client, h2_conn)) = h2::client::handshake(b).await {
            tokio::spawn(async move { let _ = h2_conn.await; });
            let req = http::Request::builder().uri("http://localhost/").body(()).unwrap();
            if let Ok((resp_fut, _send)) = client.send_request(req, true) {
                let _ = black_box(resp_fut.await);
            }
        }
        let _ = srv.await;

        // h2 0.4 client + server
        let (a4, b4) = tokio::io::duplex(4096);
        let srv4 = tokio::spawn(async move {
            if let Ok(mut conn) = h2_04::server::handshake(a4).await {
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let _ = black_box(req.uri());
                    let resp = http_1::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            }
        });
        if let Ok((mut client, h2_conn)) = h2_04::client::handshake(b4).await {
            tokio::spawn(async move { let _ = h2_conn.await; });
            let req = http_1::Request::builder().uri("http://localhost/").body(()).unwrap();
            if let Ok((resp_fut, _send)) = client.send_request(req, true) {
                let _ = black_box(resp_fut.await);
            }
        }
        let _ = srv4.await;

        // hyper 0.14 client + server + axum 0.6
        let app6 = axum::Router::new()
            .route("/info", axum::routing::post(|axum::Json(v): axum::Json<serde_json::Value>| async move { axum::Json(v) }))
            .route("/ws", axum::routing::get(|ws: axum::extract::WebSocketUpgrade| async move {
                ws.on_upgrade(|mut sock| async move {
                    while let Some(Ok(msg)) = sock.recv().await {
                        let _ = sock.send(msg).await;
                    }
                })
            }));
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let _ = axum::Server::bind(&addr).serve(app6.into_make_service()).await;
        let client14: hyper::Client<hyper::client::HttpConnector> = hyper::Client::builder().http2_only(false).build_http();
        let _ = black_box(client14.get("http://127.0.0.1/info".parse().unwrap()).await);

        // hyper 1.6 + hyper-util + axum 0.8
        let app8 = axum_08::Router::new()
            .route("/info", axum_08::routing::post(|axum_08::Json(v): axum_08::Json<serde_json::Value>| async move { axum_08::Json(v) }))
            .route("/ws", axum_08::routing::get(|ws: axum_08::extract::WebSocketUpgrade| async move {
                ws.on_upgrade(|mut sock| async move {
                    while let Some(Ok(msg)) = sock.recv().await {
                        let _ = sock.send(msg).await;
                    }
                })
            }));
        if let Ok(l) = tokio::net::TcpListener::bind("127.0.0.1:0").await {
            let _ = axum_08::serve(l, app8).await;
        }
        let client_u = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http::<http_body_util::Full<bytes::Bytes>>();
        let _ = black_box(client_u);

        // tungstenite 0.20 & 0.26 + tokio-tungstenite
        let (ta, tb) = tokio::io::duplex(1024);
        let _ = black_box(tokio_tungstenite::accept_async(ta).await);
        let _ = black_box(tokio_tungstenite::client_async("ws://127.0.0.1/ws", tb).await);
        let _ = black_box(tungstenite::client("ws://127.0.0.1/ws", std::io::Cursor::new(Vec::<u8>::new())));
        let _ = black_box(tungstenite_26::client("ws://127.0.0.1/ws", std::io::Cursor::new(Vec::<u8>::new())));
    }
    // httparse + httpdate + mime
    let mut hdrs = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut hdrs);
    let _ = black_box(req.parse(black_box(b"POST /info HTTP/1.1\r\nHost: api.hyperliquid.xyz\r\nContent-Type: application/json\r\n\r\n")));
    let _ = black_box(httpdate::parse_http_date(black_box("Thu, 27 Nov 2026 00:00:00 GMT")));
    let _ = black_box("application/json; charset=utf-8".parse::<mime::Mime>());
}

fn exercise_tracing_clap_sync_std() {
    // tracing-subscriber heavy TLS paths
    use tracing_subscriber::layer::SubscriberExt;
    let filter = tracing_subscriber::EnvFilter::try_new(black_box("info,hyper=warn,h2=error")).unwrap();
    let sub = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(true).with_thread_ids(true).with_thread_names(true));
    let _guard = tracing::subscriber::set_default(sub);
    let span = tracing::info_span!("node_step", height = 100u64, chain = "mainnet");
    let _enter = span.enter();
    tracing::info!(round = 5u64, "consensus step");
    tracing::warn!(err = "timeout", "peer reconnect");

    // clap 4.5 deep parser + help formatting
    let cmd = clap::Command::new("hl-node")
        .version("1.0")
        .about("Hyperliquid node")
        .arg(clap::Arg::new("chain").long("chain").short('c').default_value("Mainnet").value_parser(["Mainnet", "Testnet", "Local"]))
        .arg(clap::Arg::new("verbose").short('v').action(clap::ArgAction::Count))
        .subcommand(clap::Command::new("run-non-validator").arg(clap::Arg::new("write-fills").long("write-fills").action(clap::ArgAction::SetTrue)));
    let _ = black_box(cmd.clone().try_get_matches_from(["hl-node", "--chain", "Testnet", "-vv", "run-non-validator", "--write-fills"]));
    let _ = black_box(cmd.clone().try_get_matches_from(["hl-node", "--help"]));
    let _ = black_box(cmd.clone().render_long_help().to_string());

    // flate2 gzip/zlib/deflate
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(black_box(b"hyperliquid block payload 0123456789 repeated repeated"));
    if let Ok(gz) = enc.finish() {
        let mut dec = flate2::read::GzDecoder::new(&gz[..]);
        let mut out = Vec::new();
        let _ = dec.read_to_end(&mut out);
        let _ = black_box(out);
    }

    // regex + url + idna + rand + rayon + parking_lot + crossbeam + arc-swap + once_cell
    let re = regex::Regex::new(black_box(r"^(?P<chain>Mainnet|Testnet):(\d+):([0-9a-f]{40})$")).unwrap();
    let _ = black_box(re.captures(black_box("Mainnet:12345:0123456789abcdef0123456789abcdef01234567")));
    let _ = black_box(url::Url::parse(black_box("https://api.hyperliquid.xyz/info?type=meta")));
    let _ = black_box(idna::domain_to_ascii(black_box("api.hyperliquid.xyz")));
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let _ = black_box((rng.gen::<u64>(), rng.gen_range(0u64..1000)));
    use rayon::prelude::*;
    let sum: u64 = (0u64..256).into_par_iter().map(|x| x.wrapping_mul(3)).sum();
    let _ = black_box(sum);
    let m = parking_lot::Mutex::new(VecDeque::<u64>::new());
    m.lock().push_back(sum);
    let guard = crossbeam_epoch::pin();
    guard.defer(|| { black_box(1u8); });
    let w = crossbeam_deque::Worker::<u64>::new_fifo();
    w.push(1);
    let _ = black_box(w.stealer().steal());
    let asw = arc_swap::ArcSwap::from_pointee(42u64);
    let _ = black_box(**asw.load());
    static OC: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();
    let _ = black_box(OC.get_or_init(|| "init".into()));
}

fn main() {
    exercise_tracing_clap_sync_std();
    let rt_cur = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt_cur.block_on(async {
        let _ = black_box(tokio::time::sleep(Duration::from_micros(1)).await);
    });
    let rt_mt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt_mt.block_on(async {
        exercise_tokio_deep().await;
        exercise_http_h2_axum_ws().await;
    });
}
