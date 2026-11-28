use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

async fn ex_tokio_all() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let _ = tx.send(vec![1u8; 8]).await;
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
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
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
    let _ = black_box(tokio::fs::read("/dev/null").await);
    let _ = black_box(tokio::process::Command::new("/bin/true").output().await);

    if black_box(false) {
        if let Ok(l) = tokio::net::TcpListener::bind("127.0.0.1:0").await {
            if let Ok((mut s, _)) = l.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut b = [0u8; 16];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(&b).await;
            }
        }
        if let Ok(udp) = tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            let mut b = [0u8; 16];
            let _ = black_box(udp.recv_from(&mut b).await);
        }
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(hyper_tls::HttpsConnector::new());
        let _ = black_box(client.get("https://api.hyperliquid.xyz/info".parse().unwrap()).await);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let make = hyper::service::make_service_fn(|_c: &hyper::server::conn::AddrStream| async {
            Ok::<_, std::convert::Infallible>(hyper::service::service_fn(|req: hyper::Request<hyper::Body>| async move {
                let b = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(b)))
            }))
        });
        let _ = hyper::Server::bind(&addr).serve(make).await;
    }
}

fn main() {
    let rt1 = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt1.block_on(async { let _ = tokio::time::sleep(Duration::from_micros(1)).await; });
    let rt2 = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt2.block_on(ex_tokio_all());
}
