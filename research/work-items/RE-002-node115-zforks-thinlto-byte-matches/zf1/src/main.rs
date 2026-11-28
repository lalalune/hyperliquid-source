use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::Duration;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_hyper_tls_1416(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        // 1. HttpsConnector::new() + full hyper 0.14.16 HTTP/1 + HTTP/2 client
        let https_default = hyper_tls::HttpsConnector::new();
        let client_https: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(16)
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .http2_initial_stream_window_size(Some(65536))
            .http2_initial_connection_window_size(Some(65536))
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(15)))
            .http2_keep_alive_timeout(Duration::from_secs(20))
            .http2_keep_alive_while_idle(true)
            .build(https_default);

        if let Ok(uri) = s.parse::<hyper::Uri>() {
            if let Ok(resp) = client_https.get(uri).await {
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }
        if let Ok(req) = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&s)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(hyper::Body::from(s.clone()))
        {
            if let Ok(resp) = client_https.request(req).await {
                let _ = core::hint::black_box(hyper::body::aggregate(resp.into_body()).await);
            }
        }

        // 2. HttpsConnector::new_with_connector(HttpConnector) with configured socket opts
        let mut http_conn = hyper::client::HttpConnector::new();
        http_conn.enforce_http(false);
        http_conn.set_nodelay(true);
        http_conn.set_keepalive(Some(Duration::from_secs(30)));
        http_conn.set_reuse_address(true);
        http_conn.set_send_buffer_size(Some(65536));
        http_conn.set_recv_buffer_size(Some(65536));
        http_conn.set_connect_timeout(Some(Duration::from_secs(10)));
        http_conn.set_happy_eyeballs_timeout(Some(Duration::from_millis(300)));
        let tls_conn = native_tls::TlsConnector::builder()
            .build()
            .unwrap();
        let https_custom = hyper_tls::HttpsConnector::from((http_conn, tls_conn.into()));
        let client_h2: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .http2_only(true)
            .build(https_custom);
        let (mut sender, chan_body) = hyper::Body::channel();
        let _ = sender.send_data(bytes::Bytes::from(s.clone())).await;
        if let Ok(req) = hyper::Request::put(&s).body(chan_body) {
            if let Ok(mut resp) = client_h2.request(req).await {
                let _ = core::hint::black_box(hyper::upgrade::on(&mut resp).await);
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }

        // 3. Direct client::conn::handshake (HTTP/1 and HTTP/2) over TcpStream
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok((mut send_req, conn)) = hyper::client::conn::Builder::new()
                .http1_writev(true)
                .handshake::<_, hyper::Body>(stream)
                .await
            {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let req = hyper::Request::get(&s).body(hyper::Body::empty()).unwrap();
                let _ = core::hint::black_box(send_req.send_request(req).await);
            }
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok((mut send_req, conn)) = hyper::client::conn::Builder::new()
                .http2_only(true)
                .handshake::<_, hyper::Body>(stream)
                .await
            {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let req = hyper::Request::post(&s)
                    .body(hyper::Body::from(s.as_bytes().to_vec()))
                    .unwrap();
                let _ = core::hint::black_box(send_req.send_request(req).await);
            }
        }

        // 4. Plain HTTP client + Server (HTTP/1 & HTTP/2)
        let client_http: hyper::Client<_, hyper::Body> = hyper::Client::new();
        if let Ok(req) = hyper::Request::delete(&s).body(hyper::Body::empty()) {
            let _ = core::hint::black_box(client_http.request(req).await);
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
            let _ = hyper::Server::bind(&addr)
                .http1_keepalive(true)
                .http2_adaptive_window(true)
                .serve(make_svc)
                .await;
        }
    });
}

#[inline(never)]
fn touch_revm_precompile_blst(arg: &str) {
    let input = arg.as_bytes();
    for spec in [
        revm_precompile::PrecompileSpecId::HOMESTEAD,
        revm_precompile::PrecompileSpecId::BYZANTIUM,
        revm_precompile::PrecompileSpecId::ISTANBUL,
        revm_precompile::PrecompileSpecId::BERLIN,
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
    let _ = core::hint::black_box(revm_precompile::bls12_381::g1_add::g1_add(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bls12_381::g1_msm::g1_msm(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bls12_381::g2_add::g2_add(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bls12_381::g2_msm::g2_msm(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bls12_381::pairing::pairing(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bls12_381::map_fp_to_g1::map_fp_to_g1(
        input, 10_000_000,
    ));
    let _ = core::hint::black_box(revm_precompile::bls12_381::map_fp2_to_g2::map_fp2_to_g2(
        input, 10_000_000,
    ));
    let _ = core::hint::black_box(revm_precompile::bn254::run_add(input, 150, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bn254::run_mul(input, 6000, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::bn254::run_pair(
        input, 34000, 45000, 10_000_000,
    ));
    let _ = core::hint::black_box(revm_precompile::modexp::byzantium_run(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::modexp::berlin_run(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::modexp::osaka_run(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::secp256k1::ec_recover_run(
        input, 10_000_000,
    ));
    let _ = core::hint::black_box(revm_precompile::secp256r1::p256_verify(input, 10_000_000));
    let _ = core::hint::black_box(revm_precompile::blake2::run(input, 10_000_000));
}

#[inline(never)]
fn touch_bincode2(arg: &str) {
    let raw = arg.as_bytes();
    let cfg_std = bincode::config::standard();
    let cfg_leg = bincode::config::legacy();
    let cfg_lim = bincode::config::standard().with_limit::<1_048_576>();

    let _ = core::hint::black_box(bincode::encode_to_vec(raw, cfg_std));
    let _ = core::hint::black_box(bincode::encode_to_vec(arg, cfg_std));
    let _ = core::hint::black_box(bincode::encode_to_vec(raw.to_vec(), cfg_leg));
    let _ = core::hint::black_box(bincode::encode_to_vec([0u8; 32], cfg_std));
    let _ = core::hint::black_box(bincode::encode_to_vec((1u64, 2u32, 3i64, true, Some(4u16)), cfg_std));

    let _ = core::hint::black_box(bincode::decode_from_slice::<Vec<u8>, _>(raw, cfg_std));
    let _ = core::hint::black_box(bincode::decode_from_slice::<String, _>(raw, cfg_std));
    let _ = core::hint::black_box(bincode::decode_from_slice::<Vec<String>, _>(raw, cfg_lim));
    let _ = core::hint::black_box(bincode::decode_from_slice::<BTreeMap<String, Vec<u8>>, _>(raw, cfg_std));
    let _ = core::hint::black_box(bincode::decode_from_slice::<HashMap<u64, [u8; 20]>, _>(raw, cfg_leg));
    let _ = core::hint::black_box(bincode::decode_from_slice::<(u64, u32, [u8; 32]), _>(raw, cfg_std));
    let mut rdr = std::io::Cursor::new(raw);
    let _ = core::hint::black_box(bincode::decode_from_std_read::<Vec<u8>, _, _>(&mut rdr, cfg_std));
    let mut out = Vec::new();
    let _ = core::hint::black_box(bincode::encode_into_std_write(arg, &mut out, cfg_std));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_hyper_tls_1416(&arg);
        touch_revm_precompile_blst(&arg);
        touch_bincode2(&arg);
    }
}
