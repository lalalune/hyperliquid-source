use std::hint::black_box;
use std::sync::Arc;
use std::time::SystemTime;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

static LAZY_CELL: once_cell::sync::Lazy<Vec<String>> = once_cell::sync::Lazy::new(|| vec!["init".into()]);

fn main() {
    // sysinfo 0.29.11
    use sysinfo::{CpuExt, DiskExt, NetworkExt, ProcessExt, System, SystemExt};
    let mut sys = System::new_all();
    sys.refresh_all();
    for cpu in sys.cpus() { let _ = black_box(cpu.cpu_usage()); }
    for disk in sys.disks() { let _ = black_box(disk.available_space()); }
    for (name, net) in sys.networks() { let _ = black_box((name, net.received())); }
    for (pid, proc_) in sys.processes().iter().take(4) { let _ = black_box((pid, proc_.memory(), proc_.name())); }
    let _ = black_box((sys.total_memory(), sys.used_memory(), sys.load_average()));

    // arc-swap 1.7.1 (thread_local! debt!)
    let sw = arc_swap::ArcSwap::from_pointee(black_box(vec![1u64, 2, 3]));
    let g = sw.load();
    let _ = black_box(g.len());
    sw.store(Arc::new(vec![4u64, 5]));
    let _ = black_box(sw.load_full());

    // bitvec 1.0.1
    use bitvec::prelude::*;
    let mut bv = bitvec![u64, Lsb0; 0; 256];
    bv.set(black_box(7), true);
    bv.set(black_box(131), true);
    let _ = black_box((bv.count_ones(), bv.first_one(), bv.last_one()));
    let mut bv_msb = bitvec![u8, Msb0; 1; 64];
    bv_msb.shift_left(black_box(3));
    let _ = black_box(bv_msb.as_raw_slice());

    // mime, textwrap, once_cell, icu_normalizer, httpdate, httparse, anyhow
    let m: Result<mime::Mime, _> = black_box("application/json; charset=utf-8").parse();
    let _ = black_box(m);
    let _ = black_box(textwrap::wrap(black_box("the quick brown fox jumps over the lazy dog repeatedly"), 16));
    let _ = black_box(LAZY_CELL.len());
    let norm = icu_normalizer::ComposingNormalizer::new_nfc();
    let _ = black_box(norm.normalize(black_box("e\u{0301}")));
    let hds = httpdate::fmt_http_date(SystemTime::now());
    let _ = black_box(httpdate::parse_http_date(&hds));
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    let _ = black_box(req.parse(black_box(b"GET /info HTTP/1.1\r\nHost: x\r\n\r\n")));
    let err = anyhow::anyhow!("err {}", black_box(42)).context("ctx");
    let _ = black_box(format!("{err:?}"));

    // tokio 1.45.1 + rayon 1.12 + parking_lot 0.12.5 + chrono 0.4.41 + url 2.5.8 + regex 1.13.1 + lz4_flex 0.14 + tungstenite 0.26 + clap 4.5
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(8);
        let _ = tx.send(black_box(7)).await;
        let _ = black_box(rx.recv().await);
        let _ = tokio::time::sleep(std::time::Duration::from_millis(0)).await;
    });
    use rayon::prelude::*;
    let mut v: Vec<u64> = (0..512).rev().collect();
    v.par_sort();
    let _ = black_box(v.par_iter().sum::<u64>());
    let pm = parking_lot::Mutex::new(black_box(0u64));
    *pm.lock() += 1;
    let _ = black_box(chrono::Utc::now().to_rfc3339());
    let _ = black_box(url::Url::parse(black_box("https://example.com/a?b=1")));
    let re = regex::Regex::new(black_box(r"[a-z]+(\d+)")).unwrap();
    let _ = black_box(re.captures(black_box("abc123")));
    let _ = black_box(tracing_subscriber::EnvFilter::try_new(black_box("info")));
    let lz = lz4_flex::compress_prepend_size(black_box(b"hello world hello world"));
    let _ = black_box(lz4_flex::decompress_size_prepended(&lz));
    let _ = black_box(tungstenite::Message::Text(black_box("hi".into())));
    let cmd = clap::Command::new("hl").arg(clap::Arg::new("x").long("x"));
    let _ = black_box(cmd.try_get_matches_from(["hl", "--x", "1"]));
}
