use std::borrow::Cow;
use std::fmt::Write as FmtWrite;
use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn exercise_log4rs_nofeat_chrono() {
    use chrono::{DateTime, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};
    let utc = Utc::now();
    let loc = Local::now();
    let fix = FixedOffset::east_opt(3600).unwrap();
    let dt_fix = utc.with_timezone(&fix);
    let mut s = String::new();
    let _ = write!(&mut s, "{}", utc.format("%Y-%m-%d %H:%M:%S%.9f %z %Z %a %A %b %B %c %r %R %T %x %X %j %U %W %G-%V-%u %+"));
    let _ = write!(&mut s, "{}", loc.format("%Y-%m-%dT%H:%M:%S%.6f%:z"));
    let _ = write!(&mut s, "{}", dt_fix.format("%a, %d %b %Y %H:%M:%S %z"));
    let _ = black_box(dt_fix.to_rfc2822());
    let _ = black_box(dt_fix.to_rfc3339());
    let _ = black_box(DateTime::parse_from_rfc2822(black_box("Fri, 27 Nov 2026 12:34:56 +0000")));
    let _ = black_box(DateTime::parse_from_rfc3339(black_box("2026-11-27T12:34:56.789Z")));
    let _ = black_box(NaiveDateTime::parse_from_str(black_box("2026-11-27 12:34:56"), "%Y-%m-%d %H:%M:%S"));
    let _ = black_box(NaiveDate::parse_from_str(black_box("2026-11-27"), "%Y-%m-%d"));
    let _ = black_box(NaiveTime::parse_from_str(black_box("12:34:56"), "%H:%M:%S"));
    let _ = black_box(s);

    use log4rs::encode::Encode;
    let enc = log4rs::encode::pattern::PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S%.3f %Z)} {h({l})} [{T}] {t} {f}:{L} - {m}{n}");
    let arg_v = black_box(42u64);
    let mut v1 = Vec::<u8>::new();
    let mut sw = log4rs::encode::writer::simple::SimpleWriter(&mut v1);
    let _ = enc.encode(
        &mut sw,
        &log::Record::builder()
            .args(format_args!("hello {}", arg_v))
            .level(log::Level::Info)
            .target("hl_node::consensus")
            .build(),
    );
    let mut v2 = Vec::<u8>::new();
    let mut aw = log4rs::encode::writer::ansi::AnsiWriter(&mut v2);
    let _ = enc.encode(
        &mut aw,
        &log::Record::builder()
            .args(format_args!("hello {}", arg_v))
            .level(log::Level::Warn)
            .target("hl_node::consensus")
            .build(),
    );
    let _ = black_box((v1, v2));
    if black_box(false) {
        let roller = Box::new(log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller::builder().base(1).build("/tmp/hl.{}.log", 10).unwrap());
        let trigger = Box::new(log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger::new(1024 * 1024));
        let policy = Box::new(log4rs::append::rolling_file::policy::compound::CompoundPolicy::new(trigger, roller));
        let rfa = log4rs::append::rolling_file::RollingFileAppender::builder().encoder(Box::new(enc)).build("/tmp/hl.log", policy).unwrap();
        let con = log4rs::append::console::ConsoleAppender::builder().build();
        let fa = log4rs::append::file::FileAppender::builder().build("/tmp/hl2.log").unwrap();
        let cfg = log4rs::Config::builder()
            .appender(log4rs::config::Appender::builder().build("rf", Box::new(rfa)))
            .appender(log4rs::config::Appender::builder().build("con", Box::new(con)))
            .appender(log4rs::config::Appender::builder().build("fa", Box::new(fa)))
            .logger(log4rs::config::Logger::builder().appender("rf").additive(false).build("hl_node::a::b", log::LevelFilter::Debug))
            .build(log4rs::config::Root::builder().appender("con").build(log::LevelFilter::Info))
            .unwrap();
        let _ = black_box(log4rs::init_config(cfg));
    }
}

async fn exercise_hyper01416_deep() {
    let b_cow = hyper::Body::from(Cow::Borrowed("static body"));
    let (mut sender, body_ch) = hyper::Body::channel();
    let _ = black_box((b_cow, body_ch));
    if black_box(false) {
        let _ = sender.send_data(bytes::Bytes::from_static(b"chunk")).await;
        let _ = sender.send_trailers(http::HeaderMap::new()).await;

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

        let client_http: hyper::Client<hyper::client::HttpConnector, hyper::Body> = hyper::Client::builder().build_http();
        let _ = black_box(client_http.get("http://127.0.0.1/info".parse().unwrap()).await);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let make = hyper::service::make_service_fn(|_c: &hyper::server::conn::AddrStream| async {
            Ok::<_, std::convert::Infallible>(hyper::service::service_fn(|req: hyper::Request<hyper::Body>| async move {
                let b = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from(b)))
            }))
        });
        let _ = hyper::Server::bind(&addr).http1_keepalive(true).http2_keep_alive_interval(Some(Duration::from_secs(10))).serve(make).await;
    }
}

fn main() {
    exercise_log4rs_nofeat_chrono();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(exercise_hyper01416_deep());
}
