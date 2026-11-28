use bitvec::prelude::*;
use chrono::{DateTime, NaiveDateTime, Utc};
use rayon::prelude::*;
use sha2::Digest as _;
use std::num::NonZeroUsize;
use std::sync::Arc;
use sysinfo::SystemExt as _;
use tikv_jemallocator::Jemalloc;
use tiny_keccak::Hasher as _;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod cli4 {
    use clap4 as clap;
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "hl", version = "1.0")]
    pub struct Cli4 {
        #[arg(short, long, env = "HL_CHAIN")]
        pub chain: Option<String>,
        #[arg(long, default_value_t = 0)]
        pub height: u64,
    }

    pub fn parse(arg: &str) -> Result<Cli4, clap::Error> {
        Cli4::try_parse_from(["hl", "--chain", arg])
    }
}

#[inline(never)]
fn touch_sys_and_codecs(arg: &str) {
    let raw = arg.as_bytes();

    // chrono parsing, formatting, serde
    let _ = core::hint::black_box(DateTime::parse_from_rfc3339(arg));
    let _ = core::hint::black_box(NaiveDateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S"));
    let _ = core::hint::black_box(Utc::now().to_rfc3339());
    let _ = core::hint::black_box(serde_json::from_str::<DateTime<Utc>>(arg));

    // ruint + primitive-types + ethabi
    let _ = core::hint::black_box(arg.parse::<ruint::aliases::U256>());
    let u = ruint::aliases::U256::from(raw.len() as u64 + 3);
    let _ = core::hint::black_box((u.checked_mul(u), u.checked_div(u), u.to_string()));
    let _ = core::hint::black_box(serde_json::to_string(&u));
    let _ = core::hint::black_box(serde_json::from_str::<primitive_types::U256>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethabi::Contract>(arg));

    // clap 2.34 + clap 4.5.42
    let _ = core::hint::black_box(
        clap::App::new("hl")
            .arg(clap::Arg::with_name("chain").long("chain").takes_value(true))
            .get_matches_from_safe(["hl", "--chain", arg]),
    );
    let _ = core::hint::black_box(cli4::parse(arg));

    // rayon + crossbeam + arc-swap + lru + indexmap + hashbrown + bitvec
    let nums: Vec<u64> = (0..64).map(|i| i + raw.len() as u64).collect();
    let sum: u64 = nums.par_iter().map(|x| x.wrapping_mul(3)).sum();
    let _ = core::hint::black_box(sum);
    let worker = crossbeam_deque::Worker::<u64>::new_fifo();
    worker.push(sum);
    let _ = core::hint::black_box((worker.stealer().steal(), worker.pop()));
    let guard = crossbeam_epoch::pin();
    let _ = core::hint::black_box(&guard);

    let sw = arc_swap::ArcSwap::from(Arc::new(arg.to_string()));
    let _ = core::hint::black_box(sw.load());
    let mut cache = lru::LruCache::new(NonZeroUsize::new(16).unwrap());
    cache.put(arg.to_string(), raw.len());
    let _ = core::hint::black_box(cache.get(arg));

    let mut im: indexmap::IndexMap<String, u64> = indexmap::IndexMap::new();
    im.insert(arg.to_string(), sum);
    let _ = core::hint::black_box(im.get(arg));

    let mut hb: hashbrown::HashMap<String, Vec<u8>> = hashbrown::HashMap::new();
    hb.insert(arg.to_string(), raw.to_vec());
    let _ = core::hint::black_box(hb.get(arg));

    let mut bv = bitvec![u8, Msb0; 0; 64];
    bv.set(raw.len() % 64, true);
    let _ = core::hint::black_box(bv.count_ones());

    // log4rs + sysinfo
    let _ = core::hint::black_box(log4rs::init_file(arg, Default::default()));
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let _ = core::hint::black_box((sys.total_memory(), sys.used_memory()));

    // lz4_flex + blake3 + sha2 + tiny-keccak + base64 + const-hex + bs58 + serde/rmp/bincode
    let comp = lz4_flex::compress_prepend_size(raw);
    let _ = core::hint::black_box(lz4_flex::decompress_size_prepended(&comp));
    let _ = core::hint::black_box(blake3::hash(raw));
    let _ = core::hint::black_box(sha2::Sha256::digest(raw));
    let mut kec = tiny_keccak::Keccak::v256();
    kec.update(raw);
    let mut kout = [0u8; 32];
    kec.finalize(&mut kout);
    let _ = core::hint::black_box(kout);
    #[allow(deprecated)]
    let _ = core::hint::black_box(base64::encode(raw));
    let _ = core::hint::black_box(const_hex::encode(raw));
    let _ = core::hint::black_box(bs58::encode(raw).into_string());
    let _ = core::hint::black_box(serde_json::from_str::<serde_json::Value>(arg));
    let _ = core::hint::black_box(rmp_serde::from_slice::<serde_json::Value>(raw));
    let _ = core::hint::black_box(bincode::deserialize::<Vec<u8>>(raw));
    let _ = core::hint::black_box(aurora_engine_modexp::modexp(raw, &[3], &[17]));
    let mut rng = rand::thread_rng();
    let _ = core::hint::black_box(rand::Rng::gen::<u64>(&mut rng));
    let _ = core::hint::black_box(anyhow::anyhow!("err {}", arg));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_sys_and_codecs(&arg);
    }
}
