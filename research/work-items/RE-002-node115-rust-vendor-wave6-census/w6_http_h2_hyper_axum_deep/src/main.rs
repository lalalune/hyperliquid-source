use std::borrow::Cow;
use std::collections::HashMap;
use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn exercise_http_matchit_bytes() {
    // Deep http 0.2.12 HeaderMap across HeaderValue, String, usize, u64!
    let mut hm = http::HeaderMap::<http::HeaderValue>::with_capacity(32);
    for (k, v) in [
        (http::header::CONTENT_TYPE, "application/json"),
        (http::header::ACCEPT, "application/json"),
        (http::header::USER_AGENT, "hl-node"),
        (http::header::HOST, "api.hyperliquid.xyz"),
        (http::header::CONNECTION, "keep-alive"),
        (http::header::TRANSFER_ENCODING, "chunked"),
    ] {
        hm.insert(k.clone(), http::HeaderValue::from_str(black_box(v)).unwrap());
        hm.append(k, http::HeaderValue::from_static("extra"));
    }
    let _ = hm.try_insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-cache"));
    let _ = hm.try_append(http::header::ACCEPT_ENCODING, http::HeaderValue::from_static("gzip"));
    let _ = black_box(hm.entry(http::header::CONTENT_LENGTH).or_insert(http::HeaderValue::from_static("0")));
    let _ = black_box(hm.get_all(http::header::ACCEPT).iter().count());
    let _ = black_box(hm.remove(http::header::CONNECTION));
    let _ = black_box(hm.drain().count());

    let mut hm_s = http::HeaderMap::<String>::with_capacity(8);
    hm_s.insert(http::header::HOST, "a".into());
    hm_s.append(http::header::HOST, "b".into());
    let _ = black_box(hm_s.remove(http::header::HOST));

    // matchit 0.7.3 Router<T>
    let mut r_u32 = matchit::Router::<u32>::new();
    let _ = r_u32.insert("/info", 1);
    let _ = r_u32.insert("/exchange", 2);
    let _ = r_u32.insert("/evm/:chain/*rest", 3);
    let _ = black_box(r_u32.at(black_box("/evm/mainnet/rpc")));
    let _ = black_box(r_u32.at_mut(black_box("/info")));

    let mut r_us = matchit::Router::<usize>::new();
    let _ = r_us.insert("/v1/:id/status", 10);
    let _ = black_box(r_us.at(black_box("/v1/42/status")));

    // bytes 1.11.1 deep Bytes / BytesMut
    use bytes::{Buf, BufMut};
    let mut bm = bytes::BytesMut::with_capacity(128);
    bm.put_slice(black_box(b"hyperliquid bytes buffer"));
    bm.put_u64(0x123456789abcdef0);
    bm.put_u32_le(0xdeadbeef);
    let b1 = bm.split_to(8).freeze();
    let b2 = bm.freeze();
    let _ = black_box((b1.slice(1..5), b2.clone().get_u64()));
}

async fn exercise_futures_want_jsonrpsee() {
    use futures_util::{future, stream, SinkExt, StreamExt};
    let f1 = Box::pin(async { black_box(1u64) });
    let f2 = Box::pin(async { black_box(2u64) });
    let _ = black_box(future::select(f1, f2).await);
    async fn ready_u64(v: u64) -> u64 { black_box(v) }
    let _ = black_box(future::select_all(vec![Box::pin(ready_u64(1)), Box::pin(ready_u64(2))]).await);
    let mut fu = stream::FuturesUnordered::new();
    fu.push(ready_u64(10));
    fu.push(ready_u64(20));
    while let Some(v) = fu.next().await { let _ = black_box(v); }

    let (mut ftx, mut frx) = futures_channel::mpsc::channel::<Vec<u8>>(16);
    let _ = ftx.send(vec![1, 2, 3]).await;
    let _ = black_box(frx.next().await);
    let (utx, mut urx) = futures_channel::mpsc::unbounded::<String>();
    let _ = utx.unbounded_send("x".into());
    let _ = black_box(urx.next().await);

    // want 0.3.2
    let (g, mut t) = want::new();
    t.want();
    let _ = black_box(g.give());

    // jsonrpsee-core/types 0.26.1 deep
    let mut module = jsonrpsee_core::server::RpcModule::new(42u64);
    let _ = module.register_method("eth_chainId", |params, ctx, _ext| {
        let _: Result<(String, u64), _> = params.parse();
        let mut seq = params.sequence();
        let _: Result<u64, _> = seq.next();
        Ok::<String, jsonrpsee_types::ErrorObjectOwned>(format!("0x{:x}", *ctx))
    });
    let _ = module.register_async_method("eth_getBlockByNumber", |params, _ctx, _ext| async move {
        let p: Result<(String, bool), _> = params.parse();
        let _ = black_box(p);
        Ok::<serde_json::Value, jsonrpsee_types::ErrorObjectOwned>(serde_json::json!({"number": "0x1"}))
    });
    let _ = black_box(module.raw_json_request(black_box(r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#), 1).await);
    let _ = black_box(module.raw_json_request(black_box(r#"{"jsonrpc":"2.0","id":"a","method":"eth_getBlockByNumber","params":["latest",true]}"#), 1).await);
    let mut batch = jsonrpsee_core::server::BatchResponseBuilder::new_with_limit(65536);
    let _ = batch.append(jsonrpsee_core::server::MethodResponse::error(
        jsonrpsee_types::Id::Str(Cow::Borrowed("a")),
        jsonrpsee_types::ErrorObject::borrowed(-32602, "Invalid params", None),
    ));
    let _ = black_box(batch.finish());
}

async fn exercise_hyper01416_h2_axum() {
    // hyper::Body From<Cow<'static, str>> + Body::channel()
    let b_cow = hyper::Body::from(Cow::Borrowed("static body"));
    let (mut sender, body_ch) = hyper::Body::channel();
    let _ = black_box((b_cow, body_ch));
    if black_box(false) {
        let _ = sender.send_data(bytes::Bytes::from_static(b"chunk")).await;
        let _ = sender.send_trailers(http::HeaderMap::new()).await;

        // hyper 0.14.16 (hyper-fork baseline!) Client HTTP + HTTPS + HTTP2
        let https = hyper_tls::HttpsConnector::new();
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build(https);
        let req = hyper::Request::post("https://api.hyperliquid.xyz/info")
            .header("content-type", "application/json")
            .body(hyper::Body::from("{\"type\":\"meta\"}"))
            .unwrap();
        let _ = black_box(client.request(req).await);

        let client_h2: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .http2_only(true)
            .build(hyper_tls::HttpsConnector::new());
        let _ = black_box(client_h2.get("https://api.hyperliquid.xyz/info".parse().unwrap()).await);

        // hyper 0.14.16 Server HTTP1 + HTTP2 over AddrStream
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let make = hyper::service::make_service_fn(|_c: &hyper::server::conn::AddrStream| async {
            Ok::<_, std::convert::Infallible>(hyper::service::service_fn(|req: hyper::Request<hyper::Body>| async move {
                let b = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(b)))
            }))
        });
        let _ = hyper::Server::bind(&addr).http1_keepalive(true).http2_keep_alive_interval(Some(Duration::from_secs(10))).serve(make).await;

        // h2 0.3.26 over TcpStream and TlsStream<TcpStream> with custom Builder settings
        if let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:80").await {
            if let Ok(mut conn) = h2::server::Builder::new()
                .initial_window_size(1_048_576)
                .initial_connection_window_size(2_097_152)
                .max_frame_size(16384)
                .max_concurrent_streams(256)
                .handshake::<_, bytes::Bytes>(stream)
                .await
            {
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let mut body = req.into_body();
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        send.reserve_capacity(16);
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            }
        }
        if let Ok(conn_tls) = native_tls::TlsConnector::new() {
            let tconn = tokio_native_tls::TlsConnector::from(conn_tls);
            if let Ok(tcp) = tokio::net::TcpStream::connect("127.0.0.1:443").await {
                if let Ok(tls) = tconn.connect("api.hyperliquid.xyz", tcp).await {
                    if let Ok((mut client, h2_conn)) = h2::client::Builder::new().handshake::<_, bytes::Bytes>(tls).await {
                        tokio::spawn(async move { let _ = h2_conn.await; });
                        let req = http::Request::builder().uri("https://api.hyperliquid.xyz/info").body(()).unwrap();
                        if let Ok((resp, mut send)) = client.send_request(req, false) {
                            let _ = send.send_data(bytes::Bytes::from_static(b"req"), true);
                            let _ = black_box(resp.await);
                        }
                    }
                }
            }
        }

        // axum 0.6.20
        let app = axum::Router::new()
            .route("/info", axum::routing::post(|axum::Json(v): axum::Json<serde_json::Value>| async move { axum::Json(v) }))
            .route("/q", axum::routing::get(|axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| async move { axum::Json(q) }));
        let _ = axum::Server::bind(&addr).serve(app.into_make_service()).await;
    }
}

fn main() {
    exercise_http_matchit_bytes();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        exercise_futures_want_jsonrpsee().await;
        exercise_hyper01416_h2_axum().await;
    });
}
