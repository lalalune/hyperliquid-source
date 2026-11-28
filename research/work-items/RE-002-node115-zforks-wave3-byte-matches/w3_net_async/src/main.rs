use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_net_and_ws(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        // hyper 0.14.32 + hyper-tls 0.5.0 client + server
        let https = hyper_tls::HttpsConnector::new();
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(60))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build(https);
        if let Ok(req) = hyper::Request::post(&s).body(hyper::Body::from(s.clone())) {
            if let Ok(resp) = client.request(req).await {
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }

        // axum 0.6.20 server with ws + json + multipart + query
        if let Ok(addr) = s.parse::<SocketAddr>() {
            let app = axum::Router::new()
                .route(
                    "/info",
                    axum::routing::post(
                        |axum::Json(v): axum::Json<serde_json::Value>| async move {
                            axum::Json(v)
                        },
                    ),
                )
                .route(
                    "/ws",
                    axum::routing::get(|ws: axum::extract::ws::WebSocketUpgrade| async move {
                        ws.on_upgrade(|mut socket| async move {
                            while let Some(Ok(msg)) = socket.recv().await {
                                let _ = socket.send(msg).await;
                            }
                        })
                    }),
                );
            let _ = axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await;
        }

        // axum 0.8.4 + hyper 1.6.0
        if let Ok(addr) = s.parse::<SocketAddr>() {
            if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
                let app = axum_08::Router::new()
                    .route(
                        "/rpc",
                        axum_08::routing::post(
                            |axum_08::Json(v): axum_08::Json<serde_json::Value>| async move {
                                axum_08::Json(v)
                            },
                        ),
                    )
                    .route(
                        "/ws",
                        axum_08::routing::get(
                            |ws: axum_08::extract::WebSocketUpgrade| async move {
                                ws.on_upgrade(|_| async {})
                            },
                        ),
                    );
                let _ = axum_08::serve(listener, app).await;
            }
        }

        // h2 0.3.26 + h2 0.4.11 client & server
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok((send_req, mut conn)) = h2::client::Builder::new()
                .initial_window_size(65536)
                .handshake::<_, bytes::Bytes>(stream)
                .await
            {
                if let Some(mut pp) = conn.ping_pong() {
                    let _ = pp.send_ping(h2::Ping::opaque());
                }
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                if let Ok(mut ready) = send_req.ready().await {
                    let req = http::Request::builder()
                        .uri("https://example.com/")
                        .body(())
                        .unwrap();
                    if let Ok((rf, mut ss)) = ready.send_request(req, false) {
                        let _ = ss.send_data(bytes::Bytes::from_static(b"hi"), true);
                        let _ = core::hint::black_box(rf.await);
                    }
                }
            }
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok((send_req, mut conn)) = h2_04::client::Builder::new()
                .initial_window_size(65536)
                .handshake::<_, bytes::Bytes>(stream)
                .await
            {
                if let Some(mut pp) = conn.ping_pong() {
                    let _ = pp.send_ping(h2_04::Ping::opaque());
                }
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                if let Ok(mut ready) = send_req.ready().await {
                    let req = http_1::Request::builder()
                        .uri("https://example.com/")
                        .body(())
                        .unwrap();
                    if let Ok((rf, mut ss)) = ready.send_request(req, false) {
                        let _ = ss.send_data(bytes::Bytes::from_static(b"hi"), true);
                        let _ = core::hint::black_box(rf.await);
                    }
                }
            }
        }

        // tokio-tungstenite WebSocket client + server
        if let Ok((mut ws, _)) = tokio_tungstenite::connect_async(&s).await {
            let _ = ws
                .send(tokio_tungstenite::tungstenite::Message::Text(s.clone()))
                .await;
            let _ = core::hint::black_box(ws.next().await);
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await {
                let _ = core::hint::black_box(ws.next().await);
            }
        }

        // url + mime + matchit + httparse + httpdate + openssl + parking_lot
        let _ = core::hint::black_box(url::Url::parse(&s));
        let _ = core::hint::black_box(s.parse::<mime::Mime>());
        let mut router = matchit::Router::new();
        let _ = router.insert("/v1/{id}", 1usize);
        let _ = core::hint::black_box(router.at(&s));
        let mut hdrs = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut hdrs);
        let _ = core::hint::black_box(req.parse(s.as_bytes()));
        let _ = core::hint::black_box(httpdate::parse_http_date(&s));
        let _ = core::hint::black_box(openssl::ssl::SslConnector::builder(
            openssl::ssl::SslMethod::tls(),
        ));
        let mu = parking_lot::Mutex::new(s.len());
        *mu.lock() += 1;
        let _ = core::hint::black_box(*mu.lock());
    });
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_net_and_ws(&arg);
    }
}
