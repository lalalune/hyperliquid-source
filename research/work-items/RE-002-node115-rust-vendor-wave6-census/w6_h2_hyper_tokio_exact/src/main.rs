use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

async fn ex_all_async() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let _ = tx.send(vec![1u8; 16]).await;
    let _ = black_box(rx.recv().await);
    let (utx, mut urx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = utx.send("x".into());
    let _ = black_box(urx.recv().await);
    let (btx, mut brx) = tokio::sync::broadcast::channel::<u64>(16);
    let _ = btx.send(1);
    let _ = black_box(brx.recv().await);
    let (wtx, mut wrx) = tokio::sync::watch::channel(0u64);
    let _ = wtx.send(1);
    let _ = black_box(wrx.changed().await);
    let (otx, orx) = tokio::sync::oneshot::channel::<u64>();
    let _ = otx.send(7);
    let _ = black_box(orx.await);

    let mu = Arc::new(tokio::sync::Mutex::new(HashMap::<String, u64>::new()));
    mu.lock().await.insert("k".into(), 1);
    let rw = Arc::new(tokio::sync::RwLock::new(BTreeMap::<u64, String>::new()));
    rw.write().await.insert(1, "v".into());
    let sem = Arc::new(tokio::sync::Semaphore::new(8));
    let _p = sem.acquire_many(2).await;
    let notify = Arc::new(tokio::sync::Notify::new());
    notify.notify_one();
    notify.notified().await;

    let mut js = tokio::task::JoinSet::new();
    js.spawn(async { tokio::task::yield_now().await; black_box(1u64) });
    js.spawn_blocking(|| black_box(2u64));
    while let Some(r) = js.join_next().await { let _ = black_box(r); }
    let local = tokio::task::LocalSet::new();
    local.run_until(async {
        let h = tokio::task::spawn_local(async { black_box(3u64) });
        let _ = black_box(h.await);
    }).await;

    let _ = tokio::time::timeout(Duration::from_millis(2), tokio::time::sleep(Duration::from_millis(1))).await;
    let mut iv = tokio::time::interval(Duration::from_millis(1));
    iv.tick().await;
    let _ = black_box(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()));
    let _ = black_box(tokio::process::Command::new("/bin/true").output().await);

    // futures-channel 0.3.31
    let (mut ftx, mut frx) = futures_channel::mpsc::channel::<bytes::Bytes>(16);
    let _ = ftx.try_send(bytes::Bytes::from_static(b"fc"));
    let _ = black_box(futures_util::StreamExt::next(&mut frx).await);
    let (futx, mut furx) = futures_channel::mpsc::unbounded::<Vec<u8>>();
    let _ = futx.unbounded_send(vec![1, 2, 3]);
    let _ = black_box(futures_util::StreamExt::next(&mut furx).await);
    let (fotx, forx) = futures_channel::oneshot::channel::<u64>();
    let _ = fotx.send(9);
    let _ = black_box(forx.await);

    if black_box(false) {
        if let Ok(sock) = tokio::net::TcpSocket::new_v4() {
            let _ = sock.set_reuseaddr(true);
            let _ = sock.set_nodelay(true);
            let _ = sock.bind("127.0.0.1:0".parse().unwrap());
            if let Ok(l) = sock.listen(128) {
                if let Ok((mut s, _)) = l.accept().await {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut b = [0u8; 64];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(&b).await;
                    let _ = s.shutdown().await;
                    // tokio-util LengthDelimitedCodec
                    let mut framed = tokio_util::codec::LengthDelimitedCodec::builder()
                        .max_frame_length(1 << 20)
                        .new_framed(s);
                    let _ = black_box(futures_util::StreamExt::next(&mut framed).await);
                }
            }
        }
        if let Ok(s) = tokio::net::TcpStream::connect("127.0.0.1:80").await {
            let mut sb = h2::server::Builder::new();
            sb.initial_window_size(65536).max_frame_size(16384).max_concurrent_streams(100);
            if let Ok(mut conn) = sb.handshake::<_, bytes::Bytes>(s).await {
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let _ = black_box(req.uri());
                    if let Ok(mut send) = respond.send_response(http::Response::new(()), false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            }
        }
        if let Ok(s) = tokio::net::TcpStream::connect("127.0.0.1:80").await {
            let mut cb = h2::client::Builder::new();
            cb.initial_window_size(65536).max_frame_size(16384).enable_push(false);
            if let Ok((send_req, conn)) = cb.handshake::<_, bytes::Bytes>(s).await {
                tokio::spawn(async move { let _ = conn.await; });
                if let Ok(mut ready) = send_req.ready().await {
                    if let Ok((resp_fut, mut send_stream)) = ready.send_request(http::Request::new(()), false) {
                        let _ = send_stream.send_data(bytes::Bytes::from_static(b"hi"), true);
                        if let Ok(resp) = resp_fut.await {
                            let mut body = resp.into_body();
                            while let Some(chunk) = body.data().await {
                                let _ = black_box(chunk);
                            }
                        }
                    }
                }
            }
        }
        if let Ok(s) = tokio::net::TcpStream::connect("127.0.0.1:443").await {
            if let Ok(cx) = native_tls::TlsConnector::new() {
                let cx = tokio_native_tls::TlsConnector::from(cx);
                if let Ok(tls) = cx.connect("example.com", s).await {
                    let _ = black_box(h2::client::handshake(tls).await);
                }
            }
        }
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .http2_only(false)
            .pool_idle_timeout(Duration::from_secs(30))
            .build(hyper_tls::HttpsConnector::new());
        let _ = black_box(client.get("https://api.hyperliquid.xyz/info".parse().unwrap()).await);
        let client2: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .http2_only(true)
            .build(hyper_tls::HttpsConnector::new());
        let _ = black_box(client2.get("https://api.hyperliquid.xyz/info".parse().unwrap()).await);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let app = axum::Router::new()
            .route("/info", axum::routing::post(|axum::Json(v): axum::Json<serde_json::Value>| async move { axum::Json(v) }))
            .route("/health/:id", axum::routing::get(|axum::extract::Path(id): axum::extract::Path<String>| async move { id }))
            .route("/q", axum::routing::get(|axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| async move { format!("{:?}", q) }));
        let _ = axum::Server::bind(&addr).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await;
    }
}

fn ex_sync_exact() {
    use bytes::{Buf, BufMut, BytesMut};
    let mut hm = http::HeaderMap::with_capacity(16);
    for i in 0..24u32 {
        let k = http::header::HeaderName::from_bytes(format!("x-hdr-{}", i).as_bytes()).unwrap();
        let v = http::HeaderValue::from_str(&format!("val-{}", i)).unwrap();
        hm.insert(k.clone(), v.clone());
        hm.append(k, v);
    }
    let _ = black_box(hm.get("x-hdr-1").cloned());
    let _ = black_box(hm.remove("x-hdr-2"));
    let _ = black_box(hm.drain().count());

    let mut bm = BytesMut::with_capacity(64);
    bm.put_u64(0x123456789abcdef0);
    bm.put_slice(b"hyperliquid-bytes-test-payload-0123456789");
    bm.reserve(256);
    let b1 = bm.split_to(8).freeze();
    let b2 = bm.split_off(12).freeze();
    let mut ch = b1.chain(b2.slice(2..10)).take(12);
    let mut dst = [0u8; 12];
    ch.copy_to_slice(&mut dst);
    black_box(dst);

    let mut hdrs = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut hdrs);
    let _ = black_box(req.parse(b"GET /info HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n"));
    let mut rhdrs = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut rhdrs);
    let _ = black_box(resp.parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
    let _ = black_box(httparse::parse_chunk_size(b"1a\r\n"));

    let mut sl = slab::Slab::<u64>::with_capacity(32);
    for i in 0..40u64 { sl.insert(i); }
    sl.remove(5);
    sl.compact(|v, _, _| *v > 2);
    black_box(sl);

    let cv = parking_lot::Condvar::new();
    let pm = parking_lot::Mutex::new(0u64);
    let prw = parking_lot::RwLock::new(0u64);
    let mut g = pm.lock();
    *g += 1;
    let _ = cv.wait_for(&mut g, Duration::from_nanos(1));
    drop(g);
    *prw.write() += 1;
    black_box(*prw.read());

    let (g, mut t) = want::new();
    t.want();
    g.give();
    black_box((g, t));

    // crossbeam-deque 0.8.5 + rayon 1.10.0 + rayon-core 1.12.1 + smallvec 1.13.2
    let w = crossbeam_deque::Worker::<u64>::new_fifo();
    for i in 0..64u64 { w.push(i); }
    let st = w.stealer();
    let inj = crossbeam_deque::Injector::<u64>::new();
    for i in 0..32u64 { inj.push(i); }
    let _ = black_box((w.pop(), st.steal(), st.steal_batch(&w), inj.steal(), inj.steal_batch(&w)));

    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
    pool.install(|| {
        let mut v: Vec<u64> = (0..1024).rev().collect();
        v.par_sort();
        let s: u64 = v.par_iter().map(|x| x.wrapping_mul(3)).sum();
        rayon::join(|| black_box(s), || black_box(v.len()));
    });

    let mut sv: smallvec::SmallVec<[u8; 32]> = smallvec::SmallVec::new();
    sv.extend_from_slice(black_box(&[1u8; 64]));
    sv.insert(3, 9);
    sv.remove(2);
    black_box(sv.into_vec());
}

fn main() {
    ex_sync_exact();
    let rt1 = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt1.block_on(async { let _ = tokio::time::sleep(Duration::from_micros(1)).await; });
    let rt2 = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt2.block_on(ex_all_async());
}
