use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn exercise_sync_net() {
    // bytes
    let mut b = bytes::BytesMut::with_capacity(black_box(128));
    bytes::BufMut::put_slice(&mut b, black_box(b"hello world 0123456789"));
    bytes::BufMut::put_u64(&mut b, black_box(42));
    let frozen = b.freeze();
    let _ = black_box(frozen.slice(0..5));

    // mio + socket2 0.5 & 0.4
    if let Ok(mut poll) = mio::Poll::new() {
        let mut events = mio::Events::with_capacity(16);
        let _ = black_box(poll.poll(&mut events, Some(Duration::from_millis(0))));
    }
    if let Ok(s5) = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
        let _ = s5.set_nonblocking(true);
        let _ = s5.set_nodelay(true);
        let _ = s5.set_reuse_address(true);
        let _ = s5.set_recv_buffer_size(65536);
        let _ = s5.set_send_buffer_size(65536);
        let _ = black_box(s5.local_addr());
    }
    if let Ok(s4) = socket2_04::Socket::new(socket2_04::Domain::IPV4, socket2_04::Type::STREAM, Some(socket2_04::Protocol::TCP)) {
        let _ = s4.set_nonblocking(true);
        let _ = s4.set_nodelay(true);
        let _ = s4.set_reuse_address(true);
        let _ = black_box(s4.local_addr());
    }

    // openssl + native-tls
    if let Ok(mut cb) = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()) {
        let _ = cb.set_verify(openssl::ssl::SslVerifyMode::PEER);
        let conn = cb.build();
        let _ = black_box(conn.configure());
    }
    if let Ok(ab) = openssl::ssl::SslAcceptor::mozilla_intermediate_v5(openssl::ssl::SslMethod::tls()) {
        let _ = black_box(ab.build());
    }
    let _ = black_box(openssl::hash::hash(openssl::hash::MessageDigest::sha256(), black_box(b"abc")));
    let _ = black_box(openssl::bn::BigNum::from_dec_str(black_box("12345678901234567890")));
    let _ = black_box(openssl::x509::X509::from_pem(black_box(b"invalid")));
    let _ = black_box(native_tls::TlsConnector::builder().danger_accept_invalid_certs(false).build());

    // tracing + tracing-subscriber
    use tracing_subscriber::layer::SubscriberExt;
    let filter = tracing_subscriber::EnvFilter::try_new(black_box("info,tokio=warn")).unwrap_or_default();
    let sub = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json());
    let disp = tracing::Dispatch::new(sub);
    tracing::dispatcher::with_default(&disp, || {
        let span = tracing::info_span!("rt_span", id = black_box(7u64));
        let _g = span.enter();
        tracing::info!(val = black_box("ok"), "event");
        tracing::warn!(err = black_box(3i32), "warn_event");
    });

    // log4rs
    let enc = Box::new(log4rs::encode::pattern::PatternEncoder::new("{d} {l} {t} - {m}{n}"));
    let _ = black_box(log4rs::encode::json::JsonEncoder::new());
    let console = log4rs::append::console::ConsoleAppender::builder().encoder(enc).build();
    let _ = black_box(
        log4rs::config::Config::builder()
            .appender(log4rs::config::Appender::builder().build("stdout", Box::new(console)))
            .build(log4rs::config::Root::builder().appender("stdout").build(log::LevelFilter::Info))
    );
    let _ = black_box(log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger::new(1024 * 1024));
    let _ = black_box(log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller::builder().build("/tmp/x.{}.log", 3));

    // tungstenite sync protocol
    let msg = tungstenite::Message::Text(black_box("hello".to_string()));
    let _ = black_box(msg.into_data());
    let _ = black_box(tungstenite::protocol::WebSocketConfig::default());
    let _ = black_box(tungstenite::client::IntoClientRequest::into_client_request(black_box("ws://127.0.0.1:9001/ws")));
}

async fn exercise_tokio() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::codec::{Framed, LengthDelimitedCodec, LinesCodec};
    use futures_util::{SinkExt, StreamExt};

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let _ = tx.send(vec![1, 2, 3]).await;
    let _ = black_box(rx.recv().await);

    let (utx, mut urx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = utx.send("hi".into());
    let _ = black_box(urx.recv().await);

    let (otx, orx) = tokio::sync::oneshot::channel::<u64>();
    let _ = otx.send(99);
    let _ = black_box(orx.await);

    let (btx, mut brx) = tokio::sync::broadcast::channel::<u64>(8);
    let _ = btx.send(11);
    let _ = black_box(brx.recv().await);

    let (wtx, mut wrx) = tokio::sync::watch::channel::<u64>(0);
    let _ = wtx.send(1);
    let _ = black_box(wrx.changed().await);

    let mtx = std::sync::Arc::new(tokio::sync::Mutex::new(0u64));
    *mtx.lock().await += 1;
    let rw = std::sync::Arc::new(tokio::sync::RwLock::new(Vec::<u8>::new()));
    rw.write().await.push(7);
    let _ = black_box(rw.read().await.len());
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let _p = sem.acquire().await;
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    notify.notify_one();
    notify.notified().await;

    let (mut a, mut b) = tokio::io::duplex(256);
    let _ = a.write_all(b"line1\n").await;
    let mut buf = [0u8; 16];
    let _ = black_box(b.read(&mut buf).await);

    let (d1, d2) = tokio::io::duplex(256);
    let mut f1 = Framed::new(d1, LinesCodec::new());
    let _ = f1.send("abc".to_string()).await;
    let mut f2 = Framed::new(d2, LengthDelimitedCodec::new());
    let _ = black_box(f2.next().await);

    let tok = tokio_util::sync::CancellationToken::new();
    tok.cancel();
    tok.cancelled().await;

    let (ftx, mut frx) = futures_channel::mpsc::channel::<u64>(4);
    let mut ftx = ftx;
    let _ = ftx.try_send(5);
    let _ = black_box(frx.next().await);

    let mut js = tokio::task::JoinSet::new();
    js.spawn(async { tokio::time::sleep(Duration::from_millis(0)).await; 42u64 });
    let _ = black_box(js.join_next().await);
    let _ = black_box(tokio::task::spawn_blocking(|| black_box(123u64)).await);
    let _ = black_box(tokio::time::timeout(Duration::from_millis(1), tokio::task::yield_now()).await);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    if let Ok(l) = tokio::net::TcpListener::bind(addr).await {
        let local = l.local_addr().unwrap();
        let c = tokio::spawn(async move { tokio::net::TcpStream::connect(local).await });
        let _ = black_box(l.accept().await);
        let _ = black_box(c.await);
    }
    let _ = black_box(tokio::net::UdpSocket::bind(addr).await);
    let _ = black_box(tokio::fs::metadata("/dev/null").await);

    // tokio-native-tls & tokio-tungstenite symbol anchoring (non-executed branch)
    if black_box(false) {
        let cx = native_tls::TlsConnector::new().unwrap();
        let cx = tokio_native_tls::TlsConnector::from(cx);
        let s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = black_box(cx.connect("localhost", s).await);
        let _ = black_box(tokio_tungstenite::connect_async("ws://127.0.0.1:9001").await);
        let s2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = black_box(tokio_tungstenite::accept_async(s2).await);
    }
}

fn main() {
    exercise_sync_net();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(exercise_tokio());
    let rt2 = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    rt2.block_on(local.run_until(async {
        let _ = tokio::task::spawn_local(async { black_box(1u64) }).await;
    }));
}
