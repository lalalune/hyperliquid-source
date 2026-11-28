use std::hint::black_box;
use std::io::{Read, Write};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    // clap 2.34.0
    let app = clap::App::new("hl-node")
        .version("1.0")
        .about("node")
        .arg(clap::Arg::with_name("chain").long("chain").takes_value(true).required(false).possible_values(&["Mainnet", "Testnet", "Local"]))
        .arg(clap::Arg::with_name("verbose").short("v").multiple(true))
        .subcommand(clap::SubCommand::with_name("run-non-validator").arg(clap::Arg::with_name("replica-cmds-style").long("replica-cmds-style").takes_value(true)));
    let _ = black_box(app.clone().get_matches_from_safe(vec!["hl-node", "--chain", "Mainnet", "run-non-validator"]));
    let mut help_buf = Vec::new();
    let _ = app.write_help(&mut help_buf);
    let _ = black_box(help_buf);

    // regex + regex-automata + regex-syntax
    let re = regex::Regex::new(black_box(r"^([a-zA-Z0-9_]+):(\d{1,10})\s+(foo|bar|baz)+$")).unwrap();
    let _ = black_box(re.captures(black_box("key_1:12345 foobar")));
    let _ = black_box(re.replace_all(black_box("a:1 foo"), "$1=$2"));
    let rset = regex::RegexSet::new([r"\d+", r"[a-z]+", r"0x[0-9a-fA-F]{40}"]).unwrap();
    let _ = black_box(rset.matches(black_box("0x1234abcd")));
    let _ = black_box(regex_syntax::parse(black_box(r"(?i)\p{L}+-\d{2,4}")));
    let _ = black_box(regex_automata::meta::Regex::new(black_box(r"[a-z]+\d+")));

    // chrono + iana-time-zone
    let now = chrono::Utc::now();
    let loc = chrono::Local::now();
    let _ = black_box(now.to_rfc3339());
    let _ = black_box(loc.format("%Y-%m-%d %H:%M:%S%.3f %z").to_string());
    let _ = black_box(chrono::DateTime::parse_from_rfc3339(black_box("2026-11-27T12:34:56Z")));
    let _ = black_box(chrono::DateTime::parse_from_rfc2822(black_box("Fri, 27 Nov 2026 12:34:56 +0000")));
    let _ = black_box(chrono::NaiveDateTime::parse_from_str(black_box("2026-11-27 12:34:56"), "%Y-%m-%d %H:%M:%S"));
    let _ = black_box(iana_time_zone::get_timezone());

    // url + idna + form_urlencoded + percent-encoding
    if let Ok(u) = url::Url::parse(black_box("https://api.hyperliquid.xyz:443/info?a=1&b=hello%20world#frag")) {
        let _ = black_box(u.join("../exchange"));
        let _ = black_box(u.host_str());
        let _ = black_box(u.query_pairs().collect::<Vec<_>>());
    }
    let _ = black_box(idna::domain_to_ascii(black_box("bücher.example")));
    let _ = black_box(idna::domain_to_unicode(black_box("xn--bcher-kva.example")));
    let encoded: String = form_urlencoded::Serializer::new(String::new()).append_pair("k", "v 1").finish();
    let _ = black_box(form_urlencoded::parse(encoded.as_bytes()).collect::<Vec<_>>());
    let _ = black_box(percent_encoding::percent_decode_str(black_box("a%20b")).decode_utf8());

    // flate2 + miniz_oxide + lz4_flex
    let payload = black_box(b"hyperliquid node115 compression test payload repeated repeated repeated".as_slice());
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = gz.write_all(payload);
    let gz_bytes = gz.finish().unwrap();
    let mut out = Vec::new();
    let _ = flate2::read::GzDecoder::new(gz_bytes.as_slice()).read_to_end(&mut out);
    let mut zl = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = zl.write_all(payload);
    let zl_bytes = zl.finish().unwrap();
    let mut out2 = Vec::new();
    let _ = flate2::read::ZlibDecoder::new(zl_bytes.as_slice()).read_to_end(&mut out2);
    let mo = miniz_oxide::deflate::compress_to_vec(payload, 6);
    let _ = black_box(miniz_oxide::inflate::decompress_to_vec(&mo));
    let lz = lz4_flex::compress_prepend_size(payload);
    let _ = black_box(lz4_flex::decompress_size_prepended(&lz));

    // rayon + rayon-core + crossbeam-epoch + crossbeam-deque
    use rayon::prelude::*;
    let mut vals: Vec<u64> = (0..black_box(1024u64)).rev().collect();
    vals.par_sort();
    let sum: u64 = vals.par_iter().map(|x| x.wrapping_mul(3)).sum();
    let _ = black_box(sum);
    let (a, b) = rayon_core::join(|| black_box(1u64), || black_box(2u64));
    let _ = black_box((a, b));
    let guard = crossbeam_epoch::pin();
    let atom = crossbeam_epoch::Atomic::new(black_box(99u64));
    let _ = black_box(atom.load(std::sync::atomic::Ordering::Acquire, &guard));
    let w = crossbeam_deque::Worker::<u64>::new_fifo();
    w.push(1);
    let st = w.stealer();
    let _ = black_box((w.pop(), st.steal()));
    let inj = crossbeam_deque::Injector::<u64>::new();
    inj.push(2);
    let _ = black_box(inj.steal());

    // parking_lot + parking_lot_core
    let pm = parking_lot::Mutex::new(black_box(0u64));
    *pm.lock() += 1;
    let prw = parking_lot::RwLock::new(vec![1u8, 2, 3]);
    prw.write().push(4);
    let _ = black_box(prw.read().len());
    let cv = parking_lot::Condvar::new();
    let _ = black_box(cv.notify_all());
    let po = parking_lot::Once::new();
    po.call_once(|| { black_box(()); });

    // rand 0.8.5 + rand_chacha + rand_core
    use rand::{Rng, SeedableRng};
    use rand::seq::SliceRandom;
    let mut trng = rand::thread_rng();
    let mut crng = rand_chacha::ChaCha20Rng::from_entropy();
    let mut buf32 = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut buf32);
    let _ = black_box((trng.gen::<u64>(), crng.gen_range(0u64..1000), buf32));
    vals.shuffle(&mut crng);

    // base64 0.20 + sha2 0.9 & 0.10 + blake3 + curve25519 + p256 + bs58 + hex
    let b64 = base64::encode(black_box(payload));
    let _ = black_box(base64::decode(&b64));
    {
        use sha2_09::Digest;
        let _ = black_box(sha2_09::Sha256::digest(payload));
        let _ = black_box(sha2_09::Sha512::digest(payload));
    }
    {
        use sha2::Digest;
        let _ = black_box(sha2::Sha256::digest(payload));
        let _ = black_box(sha2::Sha512::digest(payload));
    }
    let _ = black_box(blake3::hash(payload));
    let sc = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order(buf32);
    let pt = &sc * &curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
    let _ = black_box(pt.compress());
    let sk = p256::ecdsa::SigningKey::random(&mut crng);
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    use p256::ecdsa::signature::{Signer, Verifier};
    let sig: p256::ecdsa::Signature = sk.sign(payload);
    let _ = black_box(vk.verify(payload, &sig));
    let b58 = bs58::encode(payload).into_string();
    let _ = black_box(bs58::decode(&b58).into_vec());
    let hx = const_hex::encode(payload);
    let _ = black_box(const_hex::decode(&hx));
    use rustc_hex::{FromHex, ToHex};
    let rhx: String = payload.to_hex();
    let _ = black_box(rhx.from_hex::<Vec<u8>>());

    // std thread_local / stdio / backtrace / mpmc
    let _ = black_box(std::backtrace::Backtrace::capture());
    let (stx, srx) = std::sync::mpsc::channel::<u64>();
    let _ = stx.send(1);
    let _ = black_box(srx.recv());
}
