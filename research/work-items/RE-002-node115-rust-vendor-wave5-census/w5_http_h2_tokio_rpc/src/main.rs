use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

async fn exercise_tokio_154() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let _ = tx.send(vec![1u8; 16]).await;
    let _ = black_box(rx.recv().await);
    let (utx, mut urx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = utx.send("hi".into());
    let _ = black_box(urx.recv().await);
    let (btx, mut brx) = tokio::sync::broadcast::channel::<u64>(16);
    let _ = btx.send(1);
    let _ = black_box(brx.recv().await);
    let (wtx, mut wrx) = tokio::sync::watch::channel(0u64);
    let _ = wtx.send(2);
    let _ = black_box(wrx.changed().await);
    let (otx, orx) = tokio::sync::oneshot::channel::<Result<Vec<u8>, String>>();
    let _ = otx.send(Ok(vec![3]));
    let _ = black_box(orx.await);

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

    let _ = tokio::time::timeout(Duration::from_millis(2), tokio::time::sleep(Duration::from_millis(1))).await;
    let mut iv = tokio::time::interval(Duration::from_millis(1));
    iv.tick().await;
    let _ = black_box(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()));
    let _ = black_box(tokio::fs::read("/dev/null").await);
    let _ = black_box(tokio::process::Command::new("/bin/true").output().await);
}

async fn exercise_h2_hyper_axum_real_sockets() {
    // Exercise http 0.2.12 HeaderMap / Uri / Request / Response deeply
    let mut hm = http::HeaderMap::with_capacity(16);
    hm.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
    hm.append(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
    hm.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(black_box("Bearer tok")).unwrap());
    hm.insert(http::header::USER_AGENT, http::HeaderValue::from_static("hl-node/1.0"));
    let _ = black_box(hm.get_all(http::header::ACCEPT).iter().count());
    let _ = black_box(hm.entry(http::header::HOST).or_insert(http::HeaderValue::from_static("api.hyperliquid.xyz")));
    let _ = black_box(hm.remove(http::header::AUTHORIZATION));
    let uri: http::Uri = black_box("https://api.hyperliquid.xyz:443/info?type=meta").parse().unwrap();
    let _ = black_box((uri.scheme(), uri.authority(), uri.path_and_query(), uri.host(), uri.port_u16()));

    // Real TcpStream / TlsStream / AddrStream / MaybeHttpsStream monomorphizations of h2 & hyper!
    if black_box(false) {
        // 1. h2 0.3.26 directly over tokio::net::TcpStream (client & server)
        if let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut conn) = h2::server::Builder::new().max_concurrent_streams(128).handshake::<_, bytes::Bytes>(stream).await {
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        let _ = black_box(req.headers());
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                        }
                    }
                }
            }
        }
        if let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:1").await {
            if let Ok((mut client, h2_conn)) = h2::client::Builder::new().handshake::<_, bytes::Bytes>(stream).await {
                tokio::spawn(async move { let _ = h2_conn.await; });
                let req = http::Request::builder().uri("http://127.0.0.1/").body(()).unwrap();
                if let Ok((resp, mut send)) = client.send_request(req, false) {
                    let _ = send.send_data(bytes::Bytes::from_static(b"body"), true);
                    let _ = black_box(resp.await);
                }
            }
        }

        // 2. h2 0.3.26 over tokio_native_tls::TlsStream<tokio::net::TcpStream>
        if let Ok(conn_tls) = native_tls::TlsConnector::new() {
            let tconn = tokio_native_tls::TlsConnector::from(conn_tls);
            if let Ok(tcp) = tokio::net::TcpStream::connect("127.0.0.1:443").await {
                if let Ok(tls) = tconn.connect("api.hyperliquid.xyz", tcp).await {
                    if let Ok((mut client, h2_conn)) = h2::client::handshake(tls).await {
                        tokio::spawn(async move { let _ = h2_conn.await; });
                        let req = http::Request::builder().uri("https://api.hyperliquid.xyz/info").body(()).unwrap();
                        if let Ok((resp, _)) = client.send_request(req, true) {
                            let _ = black_box(resp.await);
                        }
                    }
                }
            }
        }

        // 3. hyper 0.14.29 Client (HTTP + HTTPS -> MaybeHttpsStream<TcpStream> with HTTP/1 & HTTP/2!)
        let https = hyper_tls::HttpsConnector::new();
        let client_tls: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build(https);
        let req = hyper::Request::post("https://api.hyperliquid.xyz/info")
            .header("content-type", "application/json")
            .body(hyper::Body::from("{\"type\":\"meta\"}"))
            .unwrap();
        let _ = black_box(client_tls.request(req).await);

        let client_h2: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .http2_only(true)
            .build(hyper_tls::HttpsConnector::new());
        let _ = black_box(client_h2.get("https://api.hyperliquid.xyz/info".parse().unwrap()).await);

        // 4. hyper 0.14.29 Server over AddrStream (HTTP/1 & HTTP/2)
        let addr16: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let make16 = hyper::service::make_service_fn(|_conn: &hyper::server::conn::AddrStream| async {
            Ok::<_, std::convert::Infallible>(hyper::service::service_fn(|req: hyper::Request<hyper::Body>| async move {
                let b = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(b)))
            }))
        });
        let _ = hyper::Server::bind(&addr16).serve(make16).await;

        // 5. axum 0.6.20 Server + Router + Extractors + WebSocketUpgrade + ConnectInfo
        let app = axum::Router::new()
            .route("/info", axum::routing::post(|
                axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
                axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
                axum::Json(v): axum::Json<serde_json::Value>,
            | async move {
                let _ = black_box((addr, q));
                axum::Json(v)
            }))
            .route("/ws", axum::routing::get(|ws: axum::extract::WebSocketUpgrade| async move {
                ws.on_upgrade(|mut sock| async move {
                    while let Some(Ok(msg)) = sock.recv().await {
                        let _ = sock.send(msg).await;
                    }
                })
            }))
            .route("/health/:id", axum::routing::get(|axum::extract::Path(id): axum::extract::Path<String>| async move { id }));
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let _ = axum::Server::bind(&addr)
            .http2_enable_connect_protocol()
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await;

        // 6. want 0.3.2
        let (g, mut t) = want::new();
        t.want();
        let _ = black_box(g.give());
    }
}

async fn exercise_jsonrpsee() {
    let mut module = jsonrpsee_core::server::RpcModule::new(42u64);
    let _ = module.register_method("eth_blockNumber", |params, ctx, _ext| {
        let _ = black_box(params.as_str());
        Ok::<String, jsonrpsee_types::ErrorObjectOwned>(format!("0x{:x}", *ctx))
    });
    let _ = module.register_async_method("eth_call", |params, ctx, _ext| async move {
        let p: Result<serde_json::Value, _> = params.parse();
        let _ = black_box((p, ctx));
        Ok::<String, jsonrpsee_types::ErrorObjectOwned>("0x".into())
    });
    let _ = module.register_subscription("eth_subscribe", "eth_subscription", "eth_unsubscribe", |params, pending, _ctx, _ext| async move {
        let _ = black_box(params.as_str());
        if let Ok(sink) = pending.accept().await {
            if let Ok(msg) = jsonrpsee_core::server::SubscriptionMessage::new(
                sink.method_name(),
                sink.subscription_id(),
                &serde_json::json!({"block": 1}),
            ) {
                let _ = sink.send(msg).await;
            }
        }
        ()
    });
    let req_str = black_box(r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#);
    let _ = black_box(module.raw_json_request(req_str, 1).await);
    let _ = black_box(module.call::<_, String>("eth_blockNumber", [0u64; 0]).await);
    let mut batch = jsonrpsee_core::server::BatchResponseBuilder::new_with_limit(1024 * 1024);
    let mr = jsonrpsee_core::server::MethodResponse::error(
        jsonrpsee_types::Id::Number(1),
        jsonrpsee_types::ErrorObject::borrowed(-32601, "Method not found", None),
    );
    let _ = batch.append(mr);
    let _ = black_box(batch.finish());
}

fn main() {
    let rt_cur = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt_cur.block_on(async {
        let _ = black_box(tokio::time::sleep(Duration::from_micros(1)).await);
    });
    let rt_mt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt_mt.block_on(async {
        exercise_tokio_154().await;
        exercise_h2_hyper_axum_real_sockets().await;
        exercise_jsonrpsee().await;
    });
}
