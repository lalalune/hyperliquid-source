use std::hint::black_box;
use std::io::{BufRead, Write};
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn deep_sysinfo() {
    use sysinfo::{ComponentExt, DiskExt, NetworkExt, NetworksExt, ProcessExt, System, SystemExt, UserExt};
    let mut sys = System::new();
    sys.refresh_cpu();
    sys.refresh_cpu_specifics(sysinfo::CpuRefreshKind::everything());
    sys.refresh_memory();
    sys.refresh_disks_list();
    sys.refresh_disks();
    sys.refresh_networks_list();
    sys.refresh_networks();
    sys.refresh_components_list();
    sys.refresh_components();
    sys.refresh_users_list();
    sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::everything());
    for c in sys.components() { let _ = black_box((c.label(), c.temperature(), c.max(), c.critical())); }
    for d in sys.disks() { let _ = black_box((d.name(), d.mount_point(), d.file_system(), d.total_space(), d.is_removable())); }
    for (n, nd) in sys.networks().iter() { let _ = black_box((n, nd.transmitted(), nd.packets_received(), nd.errors_on_received())); }
    for u in sys.users() { let _ = black_box((u.name(), u.groups())); }
    for (pid, p) in sys.processes().iter().take(4) {
        let _ = black_box((pid, p.cmd(), p.exe(), p.cwd(), p.environ(), p.cpu_usage(), p.disk_usage(), p.status(), p.start_time()));
    }
    let _ = black_box((sys.boot_time(), sys.uptime(), sys.host_name(), sys.kernel_version(), sys.long_os_version(), sys.physical_core_count()));
}

fn deep_log4rs() {
    let raw_yaml = black_box("refresh_rate: 30 seconds\nappenders:\n  stdout:\n    kind: console\nroot:\n  level: info\n  appenders:\n    - stdout\n");
    let raw: Result<log4rs::config::RawConfig, _> = serde_yaml::from_str(raw_yaml);
    if let Ok(rc) = raw {
        let _ = black_box(log4rs::init_raw_config(rc));
    }
    if black_box(false) {
        let _ = black_box(log4rs::init_file("/tmp/nonexistent_log4rs.yaml", Default::default()));
        let _ = black_box(log4rs::append::file::FileAppender::builder().build("/tmp/nonexistent.log"));
        let trig = Box::new(log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger::new(1024));
        let roll = Box::new(log4rs::append::rolling_file::policy::compound::roll::delete::DeleteRoller::new());
        let pol = Box::new(log4rs::append::rolling_file::policy::compound::CompoundPolicy::new(trig, roll));
        let _ = black_box(log4rs::append::rolling_file::RollingFileAppender::builder().build("/tmp/nonexistent_roll.log", pol));
    }
    let _ = black_box(log4rs::filter::threshold::ThresholdFilter::new(log::LevelFilter::Warn));
}

fn deep_clap() {
    let mut app = clap::App::new("hl-node")
        .version("0.1.0")
        .author("hl")
        .about("Hyperliquid node")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .setting(clap::AppSettings::VersionlessSubcommands)
        .arg(clap::Arg::with_name("chain").long("chain").short("c").takes_value(true).default_value("Mainnet").possible_values(&["Mainnet", "Testnet", "Local"]))
        .arg(clap::Arg::with_name("config").long("config").takes_value(true).conflicts_with("chain").requires("verbose"))
        .arg(clap::Arg::with_name("verbose").short("v").multiple(true).global(true))
        .arg(clap::Arg::with_name("input").index(1).multiple(true))
        .group(clap::ArgGroup::with_name("mode").args(&["chain", "config"]))
        .subcommand(
            clap::SubCommand::with_name("run-non-validator")
                .about("run non validator")
                .arg(clap::Arg::with_name("replica-cmds-style").long("replica-cmds-style").takes_value(true))
                .arg(clap::Arg::with_name("write-fills").long("write-fills"))
                .arg(clap::Arg::with_name("batch-by-block").long("batch-by-block"))
        )
        .subcommand(clap::SubCommand::with_name("run-validator").about("run validator"));
    let _ = black_box(app.clone().get_matches_from_safe(vec!["hl-node", "--chain", "Testnet", "-vv", "run-non-validator", "--write-fills"]));
    let _ = black_box(app.clone().get_matches_from_safe(vec!["hl-node", "--bad-flag"]));
    let _ = black_box(app.clone().get_matches_from_safe(vec!["hl-node", "--help"]));
    let _ = black_box(app.clone().get_matches_from_safe(vec!["hl-node", "--version"]));
    let mut buf = Vec::new();
    let _ = app.write_long_help(&mut buf);
    let _ = app.write_version(&mut buf);
    app.gen_completions_to("hl-node", clap::Shell::Bash, &mut buf);
    let _ = black_box(buf);
}

fn deep_openssl_chrono_std() {
    // openssl: X509, PKey, Signer, Verifier, Crypter, Pkcs12, SslContext
    let _ = black_box(openssl::rsa::Rsa::generate(black_box(2048)));
    if let Ok(grp) = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1) {
        if let Ok(eck) = openssl::ec::EcKey::generate(&grp) {
            if let Ok(pk) = openssl::pkey::PKey::from_ec_key(eck) {
                let _ = black_box(pk.public_key_to_pem());
                if let Ok(mut s) = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pk) {
                    let _ = s.update(black_box(b"payload"));
                    let _ = black_box(s.sign_to_vec());
                }
            }
        }
    }
    let _ = black_box(openssl::symm::encrypt(openssl::symm::Cipher::aes_256_gcm(), &[0u8; 32], Some(&[0u8; 12]), black_box(b"msg")));
    let _ = black_box(openssl::stack::Stack::<openssl::x509::X509>::new());

    // chrono: all parsing/formatting/timezone/arithmetic paths
    let now = chrono::Utc::now();
    let loc = chrono::Local::now();
    let fix = chrono::FixedOffset::east_opt(3600).unwrap();
    let _ = black_box(now.with_timezone(&fix).to_rfc2822());
    let _ = black_box(loc.format("%A %B %d %Y %H:%M:%S %Z").to_string());
    let _ = black_box(chrono::NaiveDate::parse_from_str(black_box("2026-11-27"), "%Y-%m-%d"));
    let _ = black_box(chrono::NaiveTime::parse_from_str(black_box("12:34:56.789"), "%H:%M:%S%.f"));
    let _ = black_box(serde_json::to_string(&now));
    let _ = black_box(serde_json::from_str::<chrono::DateTime<chrono::Utc>>(black_box("\"2026-11-27T00:00:00Z\"")));

    // parking_lot + crossbeam + rayon + arc-swap + rand
    let rw = Arc::new(parking_lot::RwLock::new(vec![1u64; 16]));
    {
        let up = rw.upgradable_read();
        let mut w = parking_lot::RwLockUpgradableReadGuard::upgrade(up);
        w.push(2);
    }
    let rm = parking_lot::ReentrantMutex::new(std::cell::RefCell::new(0u64));
    *rm.lock().borrow_mut() += 1;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
    pool.install(|| {
        rayon::scope(|s| { s.spawn(|_| { black_box(1u64); }); });
        rayon::broadcast(|ctx| { black_box(ctx.index()); });
    });

    // std deep TLS / io / fs / process / net / thread / backtrace / env / panic hook
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(prev_hook);
    let _ = black_box(std::backtrace::Backtrace::force_capture().to_string());
    let h = std::thread::Builder::new().name("w".into()).spawn(|| {
        let mut s = String::new();
        let _ = std::io::BufReader::new(std::io::Cursor::new(b"a\nb\n")).read_line(&mut s);
        let mut out = std::io::BufWriter::new(Vec::new());
        let _ = writeln!(out, "{s}");
        black_box((std::thread::current().name().map(str::to_string), out))
    }).unwrap();
    let _ = black_box(h.join());
    let _ = black_box(std::process::Command::new("/bin/true").output());
    let _ = black_box(std::fs::read_dir("/tmp").map(|rd| rd.take(2).collect::<Vec<_>>()));
    let _ = black_box(std::env::vars().take(2).collect::<Vec<_>>());
    let _ = black_box(std::net::TcpListener::bind("127.0.0.1:0"));
}

fn main() {
    deep_sysinfo();
    deep_log4rs();
    deep_clap();
    deep_openssl_chrono_std();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let _ = black_box(tokio::process::Command::new("/bin/true").output().await);
        let mut iv = tokio::time::interval(Duration::from_millis(1));
        iv.tick().await;
        let _ = black_box(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()));
        let _ = black_box(tokio::fs::read("/dev/null").await);
        let bar = Arc::new(tokio::sync::Barrier::new(1));
        let _ = black_box(bar.wait().await);
        let oc = tokio::sync::OnceCell::new();
        let _ = black_box(oc.get_or_init(|| async { 42u64 }).await);
    });
}
