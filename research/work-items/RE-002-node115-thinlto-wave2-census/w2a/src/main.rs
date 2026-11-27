use chrono::Datelike;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_h2_hyper_http_tokio(arg: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let s = arg.to_string();
    rt.block_on(async move {
        // Deep h2 client + server + streams + flow control + trailers + ping + reset
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok((mut send_req, mut conn)) = h2::client::Builder::new()
                .initial_window_size(65536)
                .initial_connection_window_size(131072)
                .max_frame_size(16384)
                .max_concurrent_streams(128)
                .enable_push(false)
                .handshake::<_, bytes::Bytes>(stream)
                .await
            {
                if let Some(mut pp) = conn.ping_pong() {
                    let _ = pp.send_ping(h2::Ping::opaque());
                    let _ = core::hint::black_box(futures_util::future::poll_fn(|cx| pp.poll_pong(cx)).await);
                }
                tokio::spawn(async move { let _ = conn.await; });
                if let Ok(mut ready) = send_req.ready().await {
                    let req = http::Request::builder()
                        .method(http::Method::POST)
                        .uri("https://example.com/info")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header(http::header::USER_AGENT, "hl")
                        .body(())
                        .unwrap();
                    if let Ok((resp_fut, mut send_stream)) = ready.send_request(req, false) {
                        send_stream.reserve_capacity(1024);
                        let _ = send_stream.send_data(bytes::Bytes::from_static(b"hello"), false);
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert(http::header::HeaderName::from_static("x-t"), http::HeaderValue::from_static("1"));
                        let _ = send_stream.send_trailers(trailers);
                        send_stream.send_reset(h2::Reason::NO_ERROR);
                        if let Ok(resp) = resp_fut.await {
                            let mut body = resp.into_body();
                            while let Some(Ok(chunk)) = body.data().await {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                let _ = core::hint::black_box(chunk);
                            }
                            let _ = core::hint::black_box(body.trailers().await);
                        }
                    }
                }
            }
        }
        if let Ok(stream) = tokio::net::TcpStream::connect(&s).await {
            if let Ok(mut conn) = h2::server::Builder::new()
                .initial_window_size(65536)
                .max_concurrent_streams(128)
                .handshake::<_, bytes::Bytes>(stream)
                .await
            {
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let mut body = req.into_body();
                    let _ = core::hint::black_box(body.data().await);
                    let resp = http::Response::builder().status(http::StatusCode::OK).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            }
        }

        // Deep http::HeaderMap + Uri + Request + Response
        let mut hm = http::HeaderMap::with_capacity(16);
        hm.insert(http::header::HOST, http::HeaderValue::from_static("example.com"));
        hm.append(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
        hm.append(http::header::COOKIE, http::HeaderValue::from_static("a=1"));
        hm.append(http::header::COOKIE, http::HeaderValue::from_static("b=2"));
        let _ = core::hint::black_box(hm.get_all(http::header::COOKIE).iter().count());
        let _ = core::hint::black_box(hm.remove(http::header::HOST));
        let _ = core::hint::black_box(hm.entry(http::header::AUTHORIZATION));
        let _ = core::hint::black_box(hm.drain().count());
        let _ = core::hint::black_box(s.parse::<http::Uri>());
        let _ = core::hint::black_box(http::Method::from_bytes(s.as_bytes()));
        let _ = core::hint::black_box(http::StatusCode::from_bytes(s.as_bytes()));

        // Deep hyper HTTP/1 + HTTP/2 client & server + Body + upgrade
        let https = hyper_tls::HttpsConnector::new();
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build(https);
        if let Ok(req) = hyper::Request::post(&s).body(hyper::Body::from(s.clone())) {
            if let Ok(resp) = client.request(req).await {
                let _ = core::hint::black_box(hyper::body::to_bytes(resp.into_body()).await);
            }
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            let make_svc = hyper::service::make_service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(hyper::service::service_fn(|req: hyper::Request<hyper::Body>| async move {
                    let b = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(b)))
                }))
            });
            let _ = hyper::Server::bind(&addr).http2_adaptive_window(true).serve(make_svc).await;
        }

        // Deep tokio sync / time / io / net / fs / process / signal / task
        let (tx_m, mut rx_m) = tokio::sync::mpsc::channel::<String>(16);
        let _ = tx_m.send(s.clone()).await;
        let _ = core::hint::black_box(rx_m.recv().await);
        let (tx_u, mut rx_u) = tokio::sync::mpsc::unbounded_channel::<String>();
        let _ = tx_u.send(s.clone());
        let _ = core::hint::black_box(rx_u.recv().await);
        let (tx_b, mut rx_b) = tokio::sync::broadcast::channel::<String>(16);
        let _ = tx_b.send(s.clone());
        let _ = core::hint::black_box(rx_b.recv().await);
        let (tx_w, mut rx_w) = tokio::sync::watch::channel(s.clone());
        let _ = tx_w.send(s.clone());
        let _ = core::hint::black_box(rx_w.changed().await);
        let (tx_o, rx_o) = tokio::sync::oneshot::channel::<String>();
        let _ = tx_o.send(s.clone());
        let _ = core::hint::black_box(rx_o.await);
        let sem = Arc::new(tokio::sync::Semaphore::new(4));
        let _p = sem.acquire().await;
        let rw = tokio::sync::RwLock::new(s.clone());
        let _r = rw.read().await;
        let _w = rw.write().await;
        let mtx = tokio::sync::Mutex::new(s.clone());
        let _g = mtx.lock().await;
        let notify = tokio::sync::Notify::new();
        notify.notify_waiters();
        let mut iv = tokio::time::interval(Duration::from_millis(10));
        iv.tick().await;
        let _ = tokio::time::timeout(Duration::from_millis(5), tokio::time::sleep(Duration::from_millis(1))).await;
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async { 42u64 });
        let _ = core::hint::black_box(set.join_next().await);
        let _ = core::hint::black_box(tokio::task::spawn_blocking(|| 1u64).await);
        if let Ok(sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            let mut buf = [0u8; 64];
            let _ = core::hint::black_box(sock.recv_from(&mut buf).await);
        }
        let _ = core::hint::black_box(tokio::fs::read_to_string(&s).await);
        let _ = core::hint::black_box(tokio::fs::write(&s, s.as_bytes()).await);
        let _ = core::hint::black_box(tokio::fs::read_dir(&s).await);
        let _ = core::hint::black_box(tokio::process::Command::new(&s).output().await);
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            let _ = core::hint::black_box(sig.recv().await);
        }
    });
}

#[inline(never)]
fn touch_rayon_chrono_keccak_misc(arg: &str) {
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).stack_size(2 * 1024 * 1024).build().unwrap();
    pool.install(|| {
        let mut v: Vec<u64> = (0..1024u64).into_par_iter().map(|x| x.wrapping_mul(3)).collect();
        v.par_sort();
        v.par_sort_unstable();
        let (a, b) = rayon::join(|| v.iter().sum::<u64>(), || v.len());
        rayon::scope(|s| { s.spawn(|_| { let _ = core::hint::black_box(a + b as u64); }); });
        rayon::broadcast(|ctx| { let _ = core::hint::black_box(ctx.index()); });
    });

    // keccak-asm!
    use keccak_asm::Digest;
    let mut k256h = keccak_asm::Keccak256::new();
    k256h.update(arg.as_bytes());
    let _ = core::hint::black_box(k256h.finalize());
    let mut k512h = keccak_asm::Keccak512::new();
    k512h.update(arg.as_bytes());
    let _ = core::hint::black_box(k512h.finalize());

    // primitive-types & ruint
    let u2 = primitive_types::U256::from_dec_str(arg).unwrap_or_default();
    let u5 = primitive_types::U512::from(u2);
    let _ = core::hint::black_box((u2.checked_mul(u2), u2.div_mod(primitive_types::U256::from(7u64)), u5, format!("{u2:?} {u2:x}")));
    let r2 = ruint::aliases::U256::from_str_radix(arg, 10).unwrap_or_default();
    let _ = core::hint::black_box((r2.checked_div(ruint::aliases::U256::from(3u64)), format!("{r2:?} {r2:x}")));

    // Deep chrono
    let dt = chrono::Utc::now();
    let loc = chrono::Local::now();
    let _ = core::hint::black_box((
        dt.to_rfc3339(), dt.to_rfc2822(),
        loc.format("%Y-%m-%d %H:%M:%S%.9f %z").to_string(),
        chrono::DateTime::parse_from_rfc3339(arg),
        chrono::DateTime::parse_from_rfc2822(arg),
        chrono::DateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S %z"),
        chrono::NaiveDateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S%.f"),
        chrono::NaiveDate::parse_from_str(arg, "%Y-%m-%d"),
        chrono::NaiveTime::parse_from_str(arg, "%H:%M:%S%.f"),
        chrono::NaiveDate::from_ymd_opt(2026, 11, 27).map(|d| (d.iso_week(), d.checked_add_months(chrono::Months::new(1)))),
    ));

    // Deep log4rs: console, file, rolling file, size trigger, fixed window roller, json + pattern encoder
    let _ = core::hint::black_box(log4rs::init_file(arg, Default::default()));
    let pat = log4rs::encode::pattern::PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S%.3f)} {l} {t} - {m}{n}");
    let jenc = log4rs::encode::json::JsonEncoder::new();
    let con = log4rs::append::console::ConsoleAppender::builder().encoder(Box::new(pat)).build();
    let _ = core::hint::black_box(log4rs::append::file::FileAppender::builder().encoder(Box::new(jenc)).build(arg));
    let trig = log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger::new(10_000_000);
    if let Ok(roller) = log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller::builder().build("log.{}.gz", 5) {
        let pol = log4rs::append::rolling_file::policy::compound::CompoundPolicy::new(Box::new(trig), Box::new(roller));
        let _ = core::hint::black_box(log4rs::append::rolling_file::RollingFileAppender::builder().build(arg, Box::new(pol)));
    }
    let _ = core::hint::black_box(con);

    // Deep sysinfo
    use sysinfo::{ComponentExt, CpuExt, DiskExt, NetworkExt, NetworksExt, ProcessExt, SystemExt, UserExt};
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    for p in sys.processes().values() {
        let _ = core::hint::black_box((p.name(), p.exe(), p.cmd(), p.memory(), p.cpu_usage(), p.status(), p.disk_usage()));
    }
    for d in sys.disks() {
        let _ = core::hint::black_box((d.name(), d.mount_point(), d.total_space(), d.available_space(), d.file_system()));
    }
    for (name, net) in sys.networks() {
        let _ = core::hint::black_box((name, net.received(), net.transmitted(), net.errors_on_received()));
    }
    for c in sys.components() {
        let _ = core::hint::black_box((c.label(), c.temperature()));
    }
    for u in sys.users() {
        let _ = core::hint::black_box((u.name(), u.groups()));
    }
    for cpu in sys.cpus() {
        let _ = core::hint::black_box((cpu.name(), cpu.cpu_usage(), cpu.frequency(), cpu.brand()));
    }

    // Deep clap 2.34
    let mut app = clap::App::new("hl-node")
        .version("1.0")
        .author("hl")
        .about("node")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(clap::Arg::with_name("a").short("a").long("alpha").takes_value(true).multiple(true).conflicts_with("b").requires("c").env("A"))
        .arg(clap::Arg::with_name("b").short("b").long("beta").takes_value(true).possible_values(&["x", "y"]))
        .arg(clap::Arg::with_name("c").short("c").long("gamma").default_value("1"))
        .group(clap::ArgGroup::with_name("g").args(&["a", "b"]))
        .subcommand(clap::SubCommand::with_name("run").about("run node").arg(clap::Arg::with_name("d").required(true)));
    let mut out = Vec::new();
    let _ = app.write_help(&mut out);
    let _ = app.write_long_help(&mut out);
    app.gen_completions_to("hl-node", clap::Shell::Bash, &mut out);
    app.gen_completions_to("hl-node", clap::Shell::Zsh, &mut out);
    let _ = core::hint::black_box((out, app.get_matches_from_safe(["hl-node", "run", arg])));

    // Deep bytes, bitvec, shlex, textwrap, threadpool, httparse, httpdate, mime, url, idna, openssl, ethers, ethabi
    let mut bb = bytes::BytesMut::with_capacity(64);
    bb.extend_from_slice(arg.as_bytes());
    let b1 = bb.split_to(bb.len() / 2).freeze();
    let _ = core::hint::black_box((b1, bb.freeze()));
    let mut bv = bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::repeat(false, 64);
    bv.set(3, true);
    let _ = core::hint::black_box((bv.count_ones(), bv.leading_zeros()));
    let _ = core::hint::black_box(shlex::split(arg));
    let _ = core::hint::black_box(textwrap::wrap(arg, 40));
    let tp = threadpool::ThreadPool::new(2);
    tp.execute(|| { let _ = core::hint::black_box(1u64); });
    tp.join();
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    let _ = core::hint::black_box(req.parse(arg.as_bytes()));
    let mut rheaders = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut rheaders);
    let _ = core::hint::black_box(resp.parse(arg.as_bytes()));
    let _ = core::hint::black_box(httpdate::parse_http_date(arg));
    let _ = core::hint::black_box(httpdate::fmt_http_date(SystemTime::now()));
    let _ = core::hint::black_box(arg.parse::<mime::Mime>());
    let _ = core::hint::black_box(url::Url::parse(arg));
    let _ = core::hint::black_box(idna::domain_to_ascii(arg));
    let _ = core::hint::black_box(openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()));
    let _ = core::hint::black_box(openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()));
    let _ = core::hint::black_box(openssl::x509::X509::from_pem(arg.as_bytes()));
    let _ = core::hint::black_box(openssl::pkey::PKey::private_key_from_pem(arg.as_bytes()));
    let _ = core::hint::black_box(openssl::hash::hash(openssl::hash::MessageDigest::sha256(), arg.as_bytes()));
    let _ = core::hint::black_box(ethabi::Contract::load(arg.as_bytes()));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Transaction>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Block<ethers_core::types::H256>>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::abi::Abi>(arg));
    let _ = core::hint::black_box(base64::decode(arg));
    let _ = core::hint::black_box(bs58::decode(arg).into_vec());
    let _ = core::hint::black_box(const_hex::decode(arg));
}

#[inline(never)]
fn touch_std_deep(arg: &str) {
    let bt = std::backtrace::Backtrace::force_capture();
    let _ = core::hint::black_box(format!("{bt} {bt:#?}"));
    if let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).create(true).open(arg) {
        let _ = f.seek(std::io::SeekFrom::End(0));
        let _ = f.sync_all();
        let _ = f.set_len(0);
        let mut s = String::new();
        let _ = f.read_to_string(&mut s);
        let mut r = BufReader::new(f);
        let mut line = String::new();
        let _ = r.read_line(&mut line);
        let _ = core::hint::black_box((s, line));
    }
    if let Ok(f) = std::fs::File::create(arg) {
        let mut w = BufWriter::new(f);
        let _ = w.write_all(arg.as_bytes());
        let _ = w.flush();
    }
    let _ = core::hint::black_box((
        std::fs::read(arg), std::fs::read_to_string(arg), std::fs::write(arg, arg),
        std::fs::read_dir(arg), std::fs::metadata(arg), std::fs::symlink_metadata(arg),
        std::fs::canonicalize(arg), std::fs::create_dir_all(arg), std::fs::remove_dir_all(arg),
        std::fs::remove_file(arg), std::fs::copy(arg, arg), std::fs::rename(arg, arg),
        std::fs::read_link(arg), std::fs::hard_link(arg, arg),
        std::env::var(arg), std::env::var_os(arg), std::env::current_dir(), std::env::current_exe(),
        std::env::vars().collect::<Vec<_>>(), std::env::args_os().collect::<Vec<_>>(),
        PathBuf::from(arg).canonicalize(),
        arg.parse::<IpAddr>(), arg.parse::<Ipv4Addr>(), arg.parse::<Ipv6Addr>(), arg.parse::<SocketAddr>(),
        arg.parse::<f64>(), arg.parse::<f32>(), arg.parse::<i128>(), arg.parse::<u128>(),
        std::process::Command::new(arg).arg("--x").env("K", "V").output(),
        std::panic::catch_unwind(|| core::hint::black_box(arg.len())),
        SystemTime::now(), Instant::now(),
    ));
    if let Ok(l) = TcpListener::bind(arg) { let _ = core::hint::black_box(l.accept()); }
    if let Ok(mut s) = TcpStream::connect(arg) {
        let _ = s.set_nodelay(true);
        let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
        let mut b = [0u8; 16];
        let _ = s.read(&mut b);
        let _ = s.write(&b);
    }
    if let Ok(u) = UdpSocket::bind(arg) { let mut b = [0u8; 16]; let _ = u.recv_from(&mut b); }
    let bar = Arc::new(Barrier::new(1));
    bar.wait();
    static OL: OnceLock<String> = OnceLock::new();
    let _ = core::hint::black_box(OL.get_or_init(|| arg.to_string()));
    let m = Arc::new((Mutex::new(0u64), Condvar::new()));
    let rw = Arc::new(RwLock::new(Vec::<String>::new()));
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(4);
    let _ = tx.send(arg.to_string());
    let _ = core::hint::black_box((rx.recv(), m.0.lock(), rw.write()));
    let _ = core::hint::black_box(std::thread::Builder::new().name(arg.to_string()).spawn(|| ()));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_h2_hyper_http_tokio(&arg);
        touch_rayon_chrono_keccak_misc(&arg);
        touch_std_deep(&arg);
    }
}
