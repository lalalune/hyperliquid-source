use std::net::SocketAddr;
use std::time::Duration;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_hyper_tls_1416_v2(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        let https = hyper_tls::HttpsConnector::new();
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build(https);
        if let Ok(req) = hyper::Request::post(&s).body(hyper::Body::from(s.clone())) {
            if let Ok(resp) = client.request(req).await {
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }
        let mut http_conn = hyper::client::HttpConnector::new();
        http_conn.enforce_http(false);
        http_conn.set_nodelay(true);
        let https2 = hyper_tls::HttpsConnector::new_with_connector(http_conn);
        let client2: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .http2_only(true)
            .build(https2);
        if let Ok(uri) = s.parse::<hyper::Uri>() {
            if let Ok(resp) = client2.get(uri).await {
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            let make_svc = hyper::service::make_service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(hyper::service::service_fn(
                    |req: hyper::Request<hyper::Body>| async move {
                        let b = hyper::body::to_bytes(req.into_body())
                            .await
                            .unwrap_or_default();
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(
                            b,
                        )))
                    },
                ))
            });
            let _ = hyper::Server::bind(&addr).serve(make_svc).await;
        }
    });
}

#[inline(never)]
fn touch_revm_precompile_native_blst(arg: &str) {
    let input = arg.as_bytes();
    for spec in [
        revm_precompile::PrecompileSpecId::CANCUN,
        revm_precompile::PrecompileSpecId::PRAGUE,
        revm_precompile::PrecompileSpecId::OSAKA,
    ] {
        let pre = revm_precompile::Precompiles::new(spec);
        for addr in pre.addresses() {
            if let Some(p) = pre.get(addr) {
                let _ = core::hint::black_box(p.execute(input, 10_000_000, 0));
            }
        }
    }
    let _ = core::hint::black_box(revm_precompile::kzg_point_evaluation::run(input, 10_000_000));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_hyper_tls_1416_v2(&arg);
        touch_revm_precompile_native_blst(&arg);
    }
}
