use std::hint::black_box;
use std::time::Duration;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn exercise_clap_nofeat() {
    let mut app = clap::App::new("hl-node")
        .version("0.1.0")
        .author("hl")
        .about("Hyperliquid node")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::DeriveDisplayOrder)
        .arg(
            clap::Arg::with_name("chain")
                .long("chain")
                .short("c")
                .takes_value(true)
                .default_value("Mainnet")
                .possible_values(&["Mainnet", "Testnet", "Local"])
                .env("HL_CHAIN")
                .help("chain name"),
        )
        .arg(
            clap::Arg::with_name("config")
                .long("config")
                .takes_value(true)
                .conflicts_with("chain")
                .requires("verbose")
                .validator(|s| if s.is_empty() { Err("empty".into()) } else { Ok(()) }),
        )
        .arg(clap::Arg::with_name("verbose").short("v").long("verbose").multiple(true).global(true))
        .arg(clap::Arg::with_name("input").index(1).multiple(true).min_values(1).max_values(4))
        .group(clap::ArgGroup::with_name("mode").args(&["chain", "config"]).required(false))
        .subcommand(
            clap::SubCommand::with_name("run-non-validator")
                .about("run non validator")
                .alias("rnv")
                .arg(clap::Arg::with_name("replica-cmds-style").long("replica-cmds-style").takes_value(true))
                .arg(clap::Arg::with_name("write-fills").long("write-fills"))
                .arg(clap::Arg::with_name("batch-by-block").long("batch-by-block"))
                .arg(clap::Arg::with_name("serve-eth-rpc").long("serve-eth-rpc"))
                .arg(clap::Arg::with_name("override-gossip-config").long("override-gossip-config").takes_value(true)),
        )
        .subcommand(clap::SubCommand::with_name("run-validator").about("run validator"));

    for argv in [
        vec!["hl-node", "--chain", "Testnet", "-vv", "run-non-validator", "--write-fills", "--replica-cmds-style", "recent-actions"],
        vec!["hl-node", "--bad-flag"],
        vec!["hl-node", "--help"],
        vec!["hl-node", "-h"],
        vec!["hl-node", "--version"],
        vec!["hl-node", "help", "run-non-validator"],
        vec!["hl-node", "--chain", "InvalidChain", "run-validator"],
    ] {
        let res = app.clone().get_matches_from_safe(black_box(argv));
        if let Err(e) = &res {
            let _ = black_box(e.to_string());
        }
        let _ = black_box(res);
    }
    let mut buf = Vec::new();
    let _ = app.write_help(&mut buf);
    let _ = app.write_long_help(&mut buf);
    let _ = app.write_version(&mut buf);
    let _ = app.write_long_version(&mut buf);
    for sh in [clap::Shell::Bash, clap::Shell::Fish, clap::Shell::Zsh, clap::Shell::PowerShell, clap::Shell::Elvish] {
        app.gen_completions_to("hl-node", sh, &mut buf);
    }
    let _ = black_box(buf);
}

fn exercise_chrono_deep() {
    use chrono::{Datelike, Duration as CDuration, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike, Utc};
    let now = Utc::now();
    let loc = Local::now();
    let fix = FixedOffset::east_opt(3600).unwrap();
    let _ = black_box((now.year(), now.month(), now.day(), now.ordinal(), now.weekday(), now.iso_week(), now.hour(), now.minute(), now.second(), now.nanosecond()));
    let _ = black_box(now.with_timezone(&fix).to_rfc2822());
    let _ = black_box(now.with_timezone(&fix).to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let _ = black_box(loc.format("%Y-%m-%d %H:%M:%S%.9f %z %Z %A %B %j %U %W %G-%V-%u").to_string());
    let _ = black_box(chrono::DateTime::parse_from_rfc2822(black_box("Fri, 27 Nov 2026 12:34:56 +0000")));
    let _ = black_box(chrono::DateTime::parse_from_rfc3339(black_box("2026-11-27T12:34:56.789Z")));
    let _ = black_box(chrono::DateTime::parse_from_str(black_box("2026-11-27 12:34:56 +0000"), "%Y-%m-%d %H:%M:%S %z"));
    let _ = black_box(NaiveDateTime::parse_from_str(black_box("2026-11-27T12:34:56.123"), "%Y-%m-%dT%H:%M:%S%.f"));
    let _ = black_box(NaiveDate::parse_from_str(black_box("2026-11-27"), "%Y-%m-%d"));
    let _ = black_box(NaiveTime::parse_from_str(black_box("12:34:56.789"), "%H:%M:%S%.f"));
    let ndt = NaiveDate::from_ymd_opt(2026, 11, 27).unwrap().and_hms_opt(12, 34, 56).unwrap();
    let _ = black_box(Local.from_local_datetime(&ndt));
    let _ = black_box(Utc.from_utc_datetime(&ndt) + CDuration::seconds(3600));
    let _ = black_box(chrono::format::strftime::StrftimeItems::new("%Y-%m-%d %H:%M:%S%.f %z").collect::<Vec<_>>());
    let _ = black_box(serde_json::to_string(&now));
    let _ = black_box(serde_json::from_str::<chrono::DateTime<Utc>>(black_box("\"2026-11-27T00:00:00Z\"")));
}

fn exercise_rayon_deep() {
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).thread_name(|i| format!("w-{i}")).build().unwrap();
    pool.install(|| {
        let (a, b) = rayon::join(|| black_box(1u64), || black_box(2u64));
        let _ = black_box(a + b);
        rayon::scope(|s| {
            s.spawn(|_| { black_box(10u64); });
            s.spawn_broadcast(|_, ctx| { black_box(ctx.index()); });
        });
        rayon::scope_fifo(|s| { s.spawn_fifo(|_| { black_box(20u64); }); });
        rayon::in_place_scope(|s| { s.spawn(|_| { black_box(30u64); }); });
        let _ = black_box(rayon::broadcast(|ctx| ctx.index()));

        let mut v_u64: Vec<u64> = (0u64..128).rev().collect();
        v_u64.par_sort();
        v_u64.par_sort_unstable();
        v_u64.par_sort_by(|x, y| y.cmp(x));
        v_u64.par_sort_by_key(|x| x.wrapping_mul(3));
        let _ = black_box(v_u64.par_iter().enumerate().filter_map(|(i, x)| if i % 2 == 0 { Some(*x) } else { None }).collect::<Vec<_>>());
        let _ = black_box(v_u64.par_iter().find_first(|&&x| x == 42));
        let _ = black_box(v_u64.par_iter().find_last(|&&x| x == 42));
        let _ = black_box(v_u64.par_iter().find_any(|&&x| x == 42));
        let _ = black_box(v_u64.par_chunks(16).map(|c| c.iter().sum::<u64>()).collect::<Vec<_>>());
        let _ = black_box(v_u64.into_par_iter().fold(|| 0u64, |acc, x| acc.wrapping_add(x)).reduce(|| 0u64, |a, b| a.wrapping_add(b)));

        let mut v_usize: Vec<usize> = (0usize..64).rev().collect();
        v_usize.par_sort_unstable();
        let _ = black_box(v_usize.into_par_iter().collect::<Vec<_>>());

        let mut v_str: Vec<String> = (0..32).map(|i| format!("k{i}")).collect();
        v_str.par_sort();
        let _ = black_box(v_str.par_iter().enumerate().map(|(i, s)| (i, s.len())).collect::<Vec<_>>());

        let mut v_pair: Vec<(u64, u64)> = (0u64..64).map(|i| (64 - i, i)).collect();
        v_pair.par_sort_unstable();
        let _ = black_box(v_pair.into_par_iter().map(|(x, y)| x ^ y).collect::<Vec<_>>());

        let mut v_b32: Vec<[u8; 32]> = (0u8..32).map(|i| [i; 32]).collect();
        v_b32.par_sort_unstable();
        let _ = black_box(v_b32.par_iter().find_any(|x| x[0] == 7));
    });
}

fn exercise_rocksdb_deep() {
    if black_box(false) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(1024);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);
        opts.increase_parallelism(4);
        let cache = rocksdb::Cache::new_lru_cache(16 * 1024 * 1024);
        let mut bb = rocksdb::BlockBasedOptions::default();
        bb.set_block_cache(&cache);
        bb.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&bb);

        let cfs = vec![
            rocksdb::ColumnFamilyDescriptor::new("default", opts.clone()),
            rocksdb::ColumnFamilyDescriptor::new("state", opts.clone()),
        ];
        let _ = black_box(rocksdb::DB::list_cf(&opts, "/tmp/nonexistent_rdb"));
        if let Ok(mut db) = rocksdb::DB::open_cf_descriptors(&opts, "/tmp/nonexistent_rdb", cfs) {
            let _ = db.put(b"k1", b"v1");
            let _ = black_box(db.get(b"k1"));
            let _ = black_box(db.multi_get([b"k1", b"k2"]));
            let _ = db.delete(b"k1");
            let mut wb = rocksdb::WriteBatch::default();
            wb.put(b"k2", b"v2");
            wb.delete(b"k3");
            let mut wopts = rocksdb::WriteOptions::default();
            wopts.set_sync(false);
            let _ = db.write_opt(wb, &wopts);
            let mut ropts = rocksdb::ReadOptions::default();
            ropts.set_iterate_lower_bound(b"a".to_vec());
            let mut it = db.iterator_opt(rocksdb::IteratorMode::Start, ropts);
            while let Some(Ok((k, v))) = it.next() {
                let _ = black_box((k, v));
            }
            let mut raw = db.raw_iterator();
            raw.seek_to_first();
            while raw.valid() {
                let _ = black_box((raw.key(), raw.value()));
                raw.next();
            }
            let snap = db.snapshot();
            let _ = black_box(snap.get(b"k2"));
            if let Ok(cp) = rocksdb::checkpoint::Checkpoint::new(&db) {
                let _ = cp.create_checkpoint("/tmp/nonexistent_rdb_cp");
            }
            if let Some(cf) = db.cf_handle("state") {
                let _ = db.put_cf(&cf, b"ck", b"cv");
                let _ = black_box(db.get_cf(&cf, b"ck"));
            }
            db.compact_range::<&[u8], &[u8]>(None, None);
            let _ = db.flush();
            drop(it);
            drop(raw);
            drop(snap);
            let _ = db.create_cf("extra", &opts);
            let _ = db.drop_cf("extra");
        }
        let _ = black_box(rocksdb::DB::open(&opts, "/tmp/nonexistent_rdb2"));
        let _ = black_box(rocksdb::DB::open_for_read_only(&opts, "/tmp/nonexistent_rdb2", false));
    }
}

fn exercise_log4rs_sysinfo() {
    if black_box(false) {
        let enc = Box::new(log4rs::encode::pattern::PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S%.3f)} {l} {t} - {m}{n}"));
        let roller = Box::new(log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller::builder().build("/tmp/r.{}.log", 5).unwrap());
        let trigger = Box::new(log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger::new(1024 * 1024));
        let policy = Box::new(log4rs::append::rolling_file::policy::compound::CompoundPolicy::new(trigger, roller));
        let _ = black_box(log4rs::append::rolling_file::RollingFileAppender::builder().encoder(enc).build("/tmp/r.log", policy));
        let _ = black_box(log4rs::append::console::ConsoleAppender::builder().build());
        let _ = black_box(log4rs::init_file("/tmp/nonexistent.yaml", Default::default()));
    }
    use sysinfo::{ComponentExt, DiskExt, NetworkExt, NetworksExt, ProcessExt, System, SystemExt, UserExt};
    let mut sys = System::new_all();
    sys.refresh_all();
    for c in sys.components() { let _ = black_box((c.label(), c.temperature())); }
    for d in sys.disks() { let _ = black_box((d.name(), d.available_space())); }
    for (n, nd) in sys.networks().iter() { let _ = black_box((n, nd.received())); }
    for u in sys.users() { let _ = black_box(u.name()); }
    for (pid, p) in sys.processes().iter().take(2) { let _ = black_box((pid, p.memory(), p.cpu_usage())); }
}

fn main() {
    exercise_clap_nofeat();
    exercise_chrono_deep();
    exercise_rayon_deep();
    exercise_rocksdb_deep();
    exercise_log4rs_sysinfo();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_millis(2), tokio::time::sleep(Duration::from_millis(1))).await;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(8);
        let _ = tx.send(1).await;
        let _ = black_box(rx.recv().await);
    });
}
