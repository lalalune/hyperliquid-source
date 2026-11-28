use std::fmt::Write as FmtWrite;
use std::hint::black_box;
use std::io::Write as IoWrite;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn exercise_chrono_and_log4rs() {
    use chrono::{DateTime, Datelike, Duration, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike, Utc};
    let utc = Utc::now();
    let loc = Local::now();
    let fix = FixedOffset::east_opt(3600).unwrap();
    let dt_fix = utc.with_timezone(&fix);

    // Direct DelayedFormat::write_to(&mut String) + Display -> fmt::Formatter + fmt_buf!
    let mut s = String::new();
    let _ = write!(&mut s, "{}", utc.format("%Y-%m-%d %H:%M:%S%.9f %z %Z %a %A %b %B %c %r %R %T %x %X %j %U %W %G-%V-%u %+"));
    let _ = write!(&mut s, "{}", loc.format("%Y-%m-%dT%H:%M:%S%.6f%:z"));
    let _ = write!(&mut s, "{}", dt_fix.format("%a, %d %b %Y %H:%M:%S %z"));
    let _ = black_box(utc.format("%Y-%m-%d %H:%M:%S%.3f %z").to_string());
    let _ = black_box(loc.format("%Y-%m-%d %H:%M:%S%.3f %Z").to_string());
    let _ = black_box(dt_fix.format("%+").to_string());
    let _ = black_box(utc.format("%+").to_string());
    let _ = black_box(loc.format("%+").to_string());
    let _ = black_box(dt_fix.to_rfc2822());
    let _ = black_box(dt_fix.to_rfc3339());
    let _ = black_box(dt_fix.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true));
    let _ = black_box(dt_fix.to_rfc3339_opts(chrono::SecondsFormat::Millis, false));
    let _ = black_box(utc.naive_utc().format("%Y-%m-%d %H:%M:%S%.f").to_string());
    let _ = black_box(utc.date_naive().format("%Y-%m-%d").to_string());
    let _ = black_box(utc.time().format("%H:%M:%S%.f").to_string());
    let _ = black_box((utc.year(), utc.month(), utc.day(), utc.ordinal(), utc.weekday(), utc.iso_week(), utc.hour(), utc.minute(), utc.second(), utc.nanosecond()));

    // All parsing & timezone rule paths
    let _ = black_box(DateTime::parse_from_rfc2822(black_box("Fri, 27 Nov 2026 12:34:56 +0000")));
    let _ = black_box(DateTime::parse_from_rfc3339(black_box("2026-11-27T12:34:56.789123456Z")));
    let _ = black_box(DateTime::parse_from_str(black_box("2026-11-27 12:34:56 +0200"), "%Y-%m-%d %H:%M:%S %z"));
    let _ = black_box(NaiveDateTime::parse_from_str(black_box("2026-11-27 12:34:56.789"), "%Y-%m-%d %H:%M:%S%.f"));
    let _ = black_box(NaiveDate::parse_from_str(black_box("2026-11-27"), "%Y-%m-%d"));
    let _ = black_box(NaiveTime::parse_from_str(black_box("12:34:56.789"), "%H:%M:%S%.f"));
    let mut parsed = chrono::format::Parsed::new();
    let _ = black_box(chrono::format::parse(&mut parsed, black_box("2026-11-27T12:34:56Z"), chrono::format::StrftimeItems::new("%Y-%m-%dT%H:%M:%S%#z")));
    let _ = black_box((parsed.to_datetime(), parsed.to_datetime_with_timezone(&Utc), parsed.to_naive_date(), parsed.to_naive_time(), parsed.to_naive_datetime_with_offset(0)));
    let _ = black_box(Local.timestamp_opt(black_box(1_764_200_000), 123_456_789));
    let _ = black_box(Utc.timestamp_millis_opt(black_box(1_764_200_000_000)));
    let _ = black_box(utc + Duration::seconds(black_box(86400)));
    let _ = black_box(serde_json::to_string(&utc));
    let _ = black_box(serde_json::from_str::<DateTime<Utc>>(black_box("\"2026-11-27T00:00:00Z\"")));
    let _ = black_box(serde_json::to_string(&utc.date_naive()));
    let _ = black_box(serde_json::from_str::<NaiveDate>(black_box("\"2026-11-27\"")));
    let _ = black_box(s);

    // log4rs PatternEncoder -> SimpleWriter / AnsiWriter + FixedWindowRoller + Config::builder Logger::add!
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
            .module_path(Some("hl_node::consensus"))
            .file(Some("src/lib.rs"))
            .line(Some(10))
            .build(),
    );
    let mut v2 = Vec::<u8>::new();
    let mut aw = log4rs::encode::writer::ansi::AnsiWriter(&mut v2);
    let _ = enc.encode(
        &mut aw,
        &log::Record::builder()
            .args(format_args!("hello {}", arg_v))
            .level(log::Level::Info)
            .target("hl_node::consensus")
            .module_path(Some("hl_node::consensus"))
            .file(Some("src/lib.rs"))
            .line(Some(10))
            .build(),
    );
    let _ = black_box((v1, v2));

    if black_box(false) {
        let roller = Box::new(log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller::builder().base(1).build("/tmp/hl.{}.log", 10).unwrap());
        let trigger = Box::new(log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger::new(1024 * 1024));
        let policy = Box::new(log4rs::append::rolling_file::policy::compound::CompoundPolicy::new(trigger, roller));
        let rfa = log4rs::append::rolling_file::RollingFileAppender::builder().encoder(Box::new(enc)).build("/tmp/hl.log", policy).unwrap();
        let cfg = log4rs::Config::builder()
            .appender(log4rs::config::Appender::builder().build("rf", Box::new(rfa)))
            .logger(log4rs::config::Logger::builder().appender("rf").additive(false).build("hl_node::a::b", log::LevelFilter::Debug))
            .logger(log4rs::config::Logger::builder().appender("rf").build("hl_node::c", log::LevelFilter::Warn))
            .build(log4rs::config::Root::builder().appender("rf").build(log::LevelFilter::Info))
            .unwrap();
        let _ = black_box(log4rs::init_config(cfg));
    }
}

macro_rules! ex_uint {
    ($bits:expr, $limbs:expr) => {{
        type U = ruint::Uint<$bits, $limbs>;
        let a = U::from_str_radix(black_box("123456789012345678901234567890123456789"), 10).unwrap_or(U::from(12345u64));
        let b = U::from_str_radix(black_box("deadbeefcafe0123456789"), 16).unwrap_or(U::from(7u64));
        let c = U::from_str_radix(black_box("1010101111000101"), 2).unwrap_or(U::from(3u64));
        let d = U::from_str_radix(black_box("76543210"), 8).unwrap_or(U::from(5u64));
        let m = U::from(1_000_000_007u64);
        let _ = black_box((
            a.div_rem(b),
            a.checked_div(c),
            a.checked_rem(d),
            a.mul_mod(b, m),
            a.add_mod(b, m),
            a.pow_mod(c, m),
            a.inv_mod(m),
            a.widening_mul::<$bits, $limbs, { $bits * 2 }, { ($bits * 2 + 63) / 64 }>(b),
            a.to_string(),
            format!("{a:#x} {a:#X} {a:#b} {a:#o} {a:?}"),
            serde_json::to_string(&a),
            serde_json::from_str::<U>(black_box("\"0x1234\"")),
        ));
    }};
}

fn exercise_ruint_1123() {
    ex_uint!(64, 1);
    ex_uint!(128, 2);
    ex_uint!(160, 3);
    ex_uint!(192, 3);
    ex_uint!(256, 4);
    ex_uint!(384, 6);
    ex_uint!(512, 8);
    // Direct knuth div_nxm on arbitrary limb slices
    let mut num = [0xfedcba9876543210u64, 0x123456789abcdef0, 0x5555555555555555, 0x1111111111111111, 0x2222222222222222, 0];
    let mut den = [0x0123456789abcdefu64, 0x1020304050607080, 0x0011223344556677];
    ruint::algorithms::div(&mut num, &mut den);
    let _ = black_box((num, den));
}

fn exercise_keccak_asm_016() {
    use keccak_asm::Digest;
    let msg = black_box(b"hyperliquid consensus block hash state root 0123456789abcdef");
    let mut k224 = keccak_asm::Keccak224::new(); k224.update(msg); let _ = black_box(k224.finalize());
    let mut k256 = keccak_asm::Keccak256::new(); k256.update(msg); let _ = black_box(k256.finalize());
    let mut k384 = keccak_asm::Keccak384::new(); k384.update(msg); let _ = black_box(k384.finalize());
    let mut k512 = keccak_asm::Keccak512::new(); k512.update(msg); let _ = black_box(k512.finalize());
    let mut s224 = keccak_asm::Sha3_224::new(); s224.update(msg); let _ = black_box(s224.finalize());
    let mut s256 = keccak_asm::Sha3_256::new(); s256.update(msg); let _ = black_box(s256.finalize());
    let mut s384 = keccak_asm::Sha3_384::new(); s384.update(msg); let _ = black_box(s384.finalize());
    let mut s512 = keccak_asm::Sha3_512::new(); s512.update(msg); let _ = black_box(s512.finalize());
}

macro_rules! ex_itoa_ty {
    ($v:expr) => {{
        let v = black_box($v);
        let mut buf = itoa::Buffer::new();
        let _ = black_box(buf.format(v));
        let mut vec = Vec::<u8>::with_capacity(64);
        let _ = itoa::write(&mut vec, v);
        let mut s = String::with_capacity(64);
        let _ = itoa::fmt(&mut s, v);
        let mut cur = std::io::Cursor::new(vec);
        let _ = cur.write_all(b",");
        let _ = itoa::write(&mut cur, v);
        let _ = black_box((cur, s));
    }};
}

fn exercise_itoa_048() {
    ex_itoa_ty!(127i8);
    ex_itoa_ty!(255u8);
    ex_itoa_ty!(-32000i16);
    ex_itoa_ty!(65535u16);
    ex_itoa_ty!(-1_234_567_890i32);
    ex_itoa_ty!(4_000_000_000u32);
    ex_itoa_ty!(-9_223_372_036_854_775_000i64);
    ex_itoa_ty!(18_446_744_073_709_551_000u64);
    ex_itoa_ty!(-123_456_789isize);
    ex_itoa_ty!(123_456_789usize);
    ex_itoa_ty!(-170_141_183_460_469_231_731_687_303_715_884_105_727i128);
    ex_itoa_ty!(340_282_366_920_938_463_463_374_607_431_768_211_455u128);
}

fn main() {
    exercise_chrono_and_log4rs();
    exercise_ruint_1123();
    exercise_keccak_asm_016();
    exercise_itoa_048();
}
