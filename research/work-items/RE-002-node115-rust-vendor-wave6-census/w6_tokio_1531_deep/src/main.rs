use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

async fn ex_tokio_and_h2_hyper() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let _ = tx.send(vec![1u8; 16]).await;
    let _ = black_box(rx.recv().await);
    let (tx2, mut rx2) = tokio::sync::mpsc::channel::<(u64, String)>(16);
    let _ = tx2.try_send((1, "a".into()));
    let _ = black_box(rx2.recv().await);
    let (utx, mut urx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = utx.send("x".into());
    let _ = black_box(urx.recv().await);
    let (utx2, mut urx2) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let _ = utx2.send(vec![2u8; 8]);
    let _ = black_box(urx2.recv().await);
    let (btx, mut brx) = tokio::sync::broadcast::channel::<u64>(16);
    let _ = btx.send(1);
    let _ = black_box(brx.recv().await);
    let (btx2, mut brx2) = tokio::sync::broadcast::channel::<Arc<Vec<u8>>>(16);
    let _ = btx2.send(Arc::new(vec![3u8; 4]));
    let _ = black_box(brx2.recv().await);
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
    let _r = black_box(rw.read().await.get(&1).cloned());
    let sem = Arc::new(tokio::sync::Semaphore::new(8));
    let _p = sem.acquire_many(2).await;
    let _p2 = sem.clone().acquire_owned().await;
    let notify = Arc::new(tokio::sync::Notify::new());
    notify.notify_one();
    notify.notify_waiters();
    notify.notified().await;
    let bar = Arc::new(tokio::sync::Barrier::new(1));
    let _ = black_box(bar.wait().await);

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
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    iv.tick().await;
    let _ = black_box(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()));
    let _ = black_box(tokio::process::Command::new("/bin/true").output().await);

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
                    // Direct h2 server + client over TcpStream
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
            }
        }
        if let Ok(s) = tokio::net::TcpStream::connect("127.0.0.1:80").await {
            let mut cb = h2::client::Builder::new();
            cb.initial_window_size(65536).max_frame_size(16384).enable_push(false);
            if let Ok((mut send_req, conn)) = cb.handshake::<_, bytes::Bytes>(s).await {
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

fn ex_http_bytes_want() {
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    let mut hm = http::HeaderMap::with_capacity(16);
    for i in 0..24u32 {
        let k = http::header::HeaderName::from_bytes(format!("x-hdr-{}", i).as_bytes()).unwrap();
        let v = http::HeaderValue::from_str(&format!("val-{}", i)).unwrap();
        hm.insert(k.clone(), v.clone());
        hm.append(k.clone(), v);
    }
    let _ = black_box(hm.get("x-hdr-1"));
    let _ = black_box(hm.get_all("x-hdr-2").iter().count());
    let _ = black_box(hm.remove("x-hdr-3"));
    let _ = black_box(hm.entry("x-hdr-4"));
    let _ = black_box(hm.drain().count());

    let mut bm = BytesMut::with_capacity(64);
    bm.put_u64(0x123456789abcdef0);
    bm.put_slice(b"hyperliquid-bytes-test-payload-0123456789");
    bm.reserve(256);
    let b1 = bm.split_to(8).freeze();
    let b2 = bm.split_off(12).freeze();
    let b3 = b2.slice(2..10);
    let b4 = b2.slice_ref(&b2[1..5]);
    let mut ch = b1.chain(b3).take(12);
    let mut dst = [0u8; 12];
    ch.copy_to_slice(&mut dst);
    black_box((b4, dst));

    let (mut g, mut t) = want::new();
    t.want();
    g.give();
    black_box((g, t));
}

fn ex_primitive_ruint_nybbles_hash() {
    use primitive_types::{H160, H256, U128, U256, U512};
    let a = black_box(U256::from_dec_str("1234567890123456789012345678901234567890").unwrap());
    let b = black_box(U256::from_str_radix("deadbeefcafebabe1234567890abcdef", 16).unwrap());
    let (q, r) = a.div_mod(b);
    let prod = a.full_mul(b);
    let mut be = [0u8; 32];
    let mut le = [0u8; 32];
    a.to_big_endian(&mut be);
    a.to_little_endian(&mut le);
    let a2 = U256::from_big_endian(&be);
    let a3 = U256::from_little_endian(&le);
    let p = a.overflowing_pow(U256::from(3u64));
    let mut s = String::new();
    let _ = write!(&mut s, "{} {:x} {:X} {:?} {:?}", q, r, prod, H256::from(be), H160::from_slice(&be[..20]));
    let u5 = black_box(U512::from(a) * U512::from(b) / U512::from(17u64));
    let u1 = black_box(U128::from_dec_str("98765432109876543210").unwrap() / U128::from(7u64));
    black_box((a2, a3, p, s, u5, u1));

    // ruint 1.12.3
    let ra = black_box(ruint::Uint::<256, 4>::from_str_radix("9876543210987654321098765432109876543210", 10).unwrap());
    let rb = black_box(ruint::Uint::<256, 4>::from_str_radix("123456789012345678901", 10).unwrap());
    let (rq, rr) = ra.div_rem(rb);
    let wm: ruint::Uint<512, 8> = ra.widening_mul(rb);
    let (rq5, rr5) = wm.div_rem(ruint::Uint::<512, 8>::from(ra));
    let ra3 = black_box(ruint::Uint::<160, 3>::from_str_radix("abcdef0123456789abcdef0123456789", 16).unwrap());
    let (rq3, rr3) = ra3.div_rem(ruint::Uint::<160, 3>::from(997u64));
    let _ = black_box(format!("{} {:x} {:?} {:?}", rq, rr, (rq5, rr5), (rq3, rr3)));

    // keccak-asm 0.1.6
    use keccak_asm::Digest;
    let mut k256 = keccak_asm::Keccak256::new();
    k256.update(black_box(&be[..]));
    let d256 = k256.finalize();
    let mut k512 = keccak_asm::Keccak512::new();
    k512.update(black_box(&be[..]));
    let d512 = k512.finalize();
    let mut s256 = keccak_asm::Sha3_256::new();
    s256.update(black_box(&be[..]));
    black_box((d256, d512, s256.finalize()));

    // blake3 1.7.0
    let mut bh = blake3::Hasher::new();
    let big = vec![0x5au8; 32768];
    bh.update(black_box(&big));
    let h1 = bh.finalize();
    let mut xof = bh.finalize_xof();
    let mut xout = [0u8; 128];
    xof.fill(&mut xout);
    let kh = blake3::keyed_hash(&[7u8; 32], black_box(&big));
    let dk = blake3::derive_key("hl-ctx", black_box(&big));
    black_box((h1, xout, kh, dk));
}

fn ex_rayon_deque_smallvec_chrono_idna() {
    // crossbeam-deque 0.8.5
    let w_fifo = crossbeam_deque::Worker::<u64>::new_fifo();
    let w_lifo = crossbeam_deque::Worker::<Box<dyn FnOnce() + Send>>::new_lifo();
    for i in 0..64u64 { w_fifo.push(i); }
    let st = w_fifo.stealer();
    let inj = crossbeam_deque::Injector::<u64>::new();
    for i in 0..32u64 { inj.push(i); }
    black_box((w_fifo.pop(), st.steal(), st.steal_batch(&w_fifo), inj.steal(), inj.steal_batch(&w_fifo), w_lifo.pop()));

    // rayon 1.10.0 + rayon-core 1.12.1
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
    pool.install(|| {
        let mut v: Vec<u64> = (0..1024).rev().collect();
        v.par_sort();
        let sum: u64 = v.par_iter().map(|x| x.wrapping_mul(3)).sum();
        rayon::join(|| black_box(sum), || black_box(v.len()));
    });

    // smallvec 1.13.2
    let mut sv1: smallvec::SmallVec<[u8; 32]> = smallvec::SmallVec::new();
    sv1.extend_from_slice(black_box(&[1u8; 64]));
    sv1.insert(3, 9);
    sv1.remove(2);
    sv1.retain(|x| *x > 0);
    let mut sv2: smallvec::SmallVec<[String; 4]> = smallvec::SmallVec::new();
    for i in 0..10 { sv2.push(format!("s{}", i)); }
    sv2.resize(16, String::new());
    black_box((sv1.into_vec(), sv2));

    // chrono 0.4.38 (default-features = false)
    let nd = chrono::NaiveDate::from_ymd_opt(2026, 11, 27).unwrap();
    let nd2 = nd.checked_add_months(chrono::Months::new(5)).unwrap();
    let ndt = nd.and_hms_nano_opt(12, 34, 56, 789_000_000).unwrap();
    let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(ndt, chrono::Utc);
    let s1 = dt.format("%Y-%m-%dT%H:%M:%S%.6f%z %a %b %e %j %U %W").to_string();
    let p1 = chrono::DateTime::parse_from_rfc3339("2026-11-27T12:34:56.789Z");
    let p2 = chrono::DateTime::parse_from_rfc2822("Fri, 27 Nov 2026 12:34:56 +0000");
    let p3 = chrono::NaiveDateTime::parse_from_str("2026-11-27 12:34:56", "%Y-%m-%d %H:%M:%S");
    black_box((nd2, s1, p1, p2, p3));

    // idna 1.0.3 + icu_normalizer 1.5.0 + url 2.5.4
    let u = url::Url::parse(black_box("https://bücher.example.com:8443/path/to/x?a=1&b=2#frag"));
    let d1 = idna::domain_to_ascii(black_box("bücher.example.com"));
    let d2 = idna::domain_to_unicode(black_box("xn--bcher-kva.example.com"));
    let nfc = icu_normalizer::ComposingNormalizer::new_nfc();
    let nfd = icu_normalizer::DecomposingNormalizer::new_nfd();
    black_box((u, d1, d2, nfc.normalize("e\u{0301}"), nfd.normalize("\u{00e9}")));
}

fn main() {
    ex_http_bytes_want();
    ex_primitive_ruint_nybbles_hash();
    ex_rayon_deque_smallvec_chrono_idna();
    let rt1 = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt1.block_on(async { let _ = tokio::time::sleep(Duration::from_micros(1)).await; });
    let rt2 = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt2.block_on(ex_tokio_and_h2_hyper());
}
