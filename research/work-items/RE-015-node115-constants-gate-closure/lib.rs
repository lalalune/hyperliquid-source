#![forbid(unsafe_code)]

use std::fmt;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantNotFound;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AwsName {
    Ec = 0,
    DummyTokyo = 1,
    DummyTokyo2 = 2,
    GaOnchain = 3,
    GbOnchain = 4,
    NodeTestnet = 5,
    NodeTestnet2 = 6,
    NodeTestnet3 = 7,
    NodeTestnet4 = 8,
    Ea = 9,
    Ea2 = 10,
    Ea3 = 11,
    EaMm = 12,
    EaTx = 13,
    HeavyTestnet = 14,
    HeavyMainnet = 15,
    Eb = 16,
    Ed = 17,
    Ee = 18,
    SoloTestnet = 19,
    SoloMainnet = 20,
    LockerTestnet = 21,
    LockerMainnet = 22,
    RpcTestnet = 23,
    RpcSandbox = 24,
    RpcMainnet = 25,
    RpcMainnet2 = 26,
    Sa = 27,
    Sb = 28,
    Sc = 29,
    Sd = 30,
    WebSandbox = 31,
    SoloSandbox = 32,
    NvTestnet = 33,
    NvTestnet2 = 34,
    NvMainnet = 35,
    NvMainnet2 = 36,
    NvMainnet3 = 37,
    JoinMainnet = 38,
    DummyNv = 39,
    FBinSpot = 40,
    FBinSpot2 = 41,
    FBinSpot3 = 42,
    FBinSpot4 = 43,
    FBinSpot5 = 44,
    FBinSpot6 = 45,
    FBinSpot7 = 46,
    FBinSpot8 = 47,
    FBinPerp = 48,
    FBinPerp2 = 49,
    FOkexSpot = 50,
    FOkexSpot2 = 51,
    FOkexPerp = 52,
    FHuobiSpot = 53,
    FHuobiSpot2 = 54,
    FHuobiSpot3 = 55,
    FHuobiSpot4 = 56,
    FHuobiPi = 57,
    FHuobiPerp = 58,
    FCobSpot = 59,
    FKraSpot = 60,
    FBybitSpot = 61,
    ScratchDummy = 62,
    ScratchCron = 63,
    OBinSpot = 64,
    FHlPerp = 65,
    GaHlPerp = 66,
    GaHlPerp2 = 67,
    GaHlPerp3 = 68,
    GbHlPerp = 69,
    GbHlPerp2 = 70,
    GbHlPerp3 = 71,
    GcHlPerp = 72,
    GcHlPerp2 = 73,
    GdHlPerp = 74,
    GdHlPerp2 = 75,
    GsHlPerp = 76,
    EaHlPerp = 77,
    EbHlPerp = 78,
}

/// Exact 2,246-byte node #115 `AwsName::from_str` (`0x1775500..0x1775dc6`).
#[inline(never)]
pub fn gc_aws_name_from_str(s: &str) -> Result<AwsName, VariantNotFound> {
    let v = match s {
        "Ec" => AwsName::Ec,
        "DummyTokyo" => AwsName::DummyTokyo,
        "DummyTokyo2" => AwsName::DummyTokyo2,
        "GaOnchain" => AwsName::GaOnchain,
        "GbOnchain" => AwsName::GbOnchain,
        "NodeTestnet" => AwsName::NodeTestnet,
        "NodeTestnet2" => AwsName::NodeTestnet2,
        "NodeTestnet3" => AwsName::NodeTestnet3,
        "NodeTestnet4" => AwsName::NodeTestnet4,
        "Ea" => AwsName::Ea,
        "Ea2" => AwsName::Ea2,
        "Ea3" => AwsName::Ea3,
        "EaMm" => AwsName::EaMm,
        "EaTx" => AwsName::EaTx,
        "HeavyTestnet" => AwsName::HeavyTestnet,
        "HeavyMainnet" => AwsName::HeavyMainnet,
        "Eb" => AwsName::Eb,
        "Ed" => AwsName::Ed,
        "Ee" => AwsName::Ee,
        "SoloTestnet" => AwsName::SoloTestnet,
        "SoloMainnet" => AwsName::SoloMainnet,
        "LockerTestnet" => AwsName::LockerTestnet,
        "LockerMainnet" => AwsName::LockerMainnet,
        "RpcTestnet" => AwsName::RpcTestnet,
        "RpcSandbox" => AwsName::RpcSandbox,
        "RpcMainnet" => AwsName::RpcMainnet,
        "RpcMainnet2" => AwsName::RpcMainnet2,
        "Sa" => AwsName::Sa,
        "Sb" => AwsName::Sb,
        "Sc" => AwsName::Sc,
        "Sd" => AwsName::Sd,
        "WebSandbox" => AwsName::WebSandbox,
        "SoloSandbox" => AwsName::SoloSandbox,
        "NvTestnet" => AwsName::NvTestnet,
        "NvTestnet2" => AwsName::NvTestnet2,
        "NvMainnet" => AwsName::NvMainnet,
        "NvMainnet2" => AwsName::NvMainnet2,
        "NvMainnet3" => AwsName::NvMainnet3,
        "JoinMainnet" => AwsName::JoinMainnet,
        "DummyNv" => AwsName::DummyNv,
        "FBinSpot" => AwsName::FBinSpot,
        "FBinSpot2" => AwsName::FBinSpot2,
        "FBinSpot3" => AwsName::FBinSpot3,
        "FBinSpot4" => AwsName::FBinSpot4,
        "FBinSpot5" => AwsName::FBinSpot5,
        "FBinSpot6" => AwsName::FBinSpot6,
        "FBinSpot7" => AwsName::FBinSpot7,
        "FBinSpot8" => AwsName::FBinSpot8,
        "FBinPerp" => AwsName::FBinPerp,
        "FBinPerp2" => AwsName::FBinPerp2,
        "FOkexSpot" => AwsName::FOkexSpot,
        "FOkexSpot2" => AwsName::FOkexSpot2,
        "FOkexPerp" => AwsName::FOkexPerp,
        "FHuobiSpot" => AwsName::FHuobiSpot,
        "FHuobiSpot2" => AwsName::FHuobiSpot2,
        "FHuobiSpot3" => AwsName::FHuobiSpot3,
        "FHuobiSpot4" => AwsName::FHuobiSpot4,
        "FHuobiPi" => AwsName::FHuobiPi,
        "FHuobiPerp" => AwsName::FHuobiPerp,
        "FCobSpot" => AwsName::FCobSpot,
        "FKraSpot" => AwsName::FKraSpot,
        "FBybitSpot" => AwsName::FBybitSpot,
        "ScratchDummy" => AwsName::ScratchDummy,
        "ScratchCron" => AwsName::ScratchCron,
        "OBinSpot" => AwsName::OBinSpot,
        "FHlPerp" => AwsName::FHlPerp,
        "GaHlPerp" => AwsName::GaHlPerp,
        "GaHlPerp2" => AwsName::GaHlPerp2,
        "GaHlPerp3" => AwsName::GaHlPerp3,
        "GbHlPerp" => AwsName::GbHlPerp,
        "GbHlPerp2" => AwsName::GbHlPerp2,
        "GbHlPerp3" => AwsName::GbHlPerp3,
        "GcHlPerp" => AwsName::GcHlPerp,
        "GcHlPerp2" => AwsName::GcHlPerp2,
        "GdHlPerp" => AwsName::GdHlPerp,
        "GdHlPerp2" => AwsName::GdHlPerp2,
        "GsHlPerp" => AwsName::GsHlPerp,
        "EaHlPerp" => AwsName::EaHlPerp,
        "EbHlPerp" => AwsName::EbHlPerp,
        _ => return Err(VariantNotFound),
    };
    Ok(v)
}

/// Exact 1,681-byte node #115 `AwsName::fmt` (`0x1774e60..0x17754f1`).
#[inline(never)]
pub fn gc_aws_name_fmt(v: &AwsName, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match v {
        AwsName::Ec => f.write_str("Ec"),
        AwsName::DummyTokyo => f.write_str("DummyTokyo"),
        AwsName::DummyTokyo2 => f.write_str("DummyTokyo2"),
        AwsName::GaOnchain => f.write_str("GaOnchain"),
        AwsName::GbOnchain => f.write_str("GbOnchain"),
        AwsName::NodeTestnet => f.write_str("NodeTestnet"),
        AwsName::NodeTestnet2 => f.write_str("NodeTestnet2"),
        AwsName::NodeTestnet3 => f.write_str("NodeTestnet3"),
        AwsName::NodeTestnet4 => f.write_str("NodeTestnet4"),
        AwsName::Ea => f.write_str("Ea"),
        AwsName::Ea2 => f.write_str("Ea2"),
        AwsName::Ea3 => f.write_str("Ea3"),
        AwsName::EaMm => f.write_str("EaMm"),
        AwsName::EaTx => f.write_str("EaTx"),
        AwsName::HeavyTestnet => f.write_str("HeavyTestnet"),
        AwsName::HeavyMainnet => f.write_str("HeavyMainnet"),
        AwsName::Eb => f.write_str("Eb"),
        AwsName::Ed => f.write_str("Ed"),
        AwsName::Ee => f.write_str("Ee"),
        AwsName::SoloTestnet => f.write_str("SoloTestnet"),
        AwsName::SoloMainnet => f.write_str("SoloMainnet"),
        AwsName::LockerTestnet => f.write_str("LockerTestnet"),
        AwsName::LockerMainnet => f.write_str("LockerMainnet"),
        AwsName::RpcTestnet => f.write_str("RpcTestnet"),
        AwsName::RpcSandbox => f.write_str("RpcSandbox"),
        AwsName::RpcMainnet => f.write_str("RpcMainnet"),
        AwsName::RpcMainnet2 => f.write_str("RpcMainnet2"),
        AwsName::Sa => f.write_str("Sa"),
        AwsName::Sb => f.write_str("Sb"),
        AwsName::Sc => f.write_str("Sc"),
        AwsName::Sd => f.write_str("Sd"),
        AwsName::WebSandbox => f.write_str("WebSandbox"),
        AwsName::SoloSandbox => f.write_str("SoloSandbox"),
        AwsName::NvTestnet => f.write_str("NvTestnet"),
        AwsName::NvTestnet2 => f.write_str("NvTestnet2"),
        AwsName::NvMainnet => f.write_str("NvMainnet"),
        AwsName::NvMainnet2 => f.write_str("NvMainnet2"),
        AwsName::NvMainnet3 => f.write_str("NvMainnet3"),
        AwsName::JoinMainnet => f.write_str("JoinMainnet"),
        AwsName::DummyNv => f.write_str("DummyNv"),
        AwsName::FBinSpot => f.write_str("FBinSpot"),
        AwsName::FBinSpot2 => f.write_str("FBinSpot2"),
        AwsName::FBinSpot3 => f.write_str("FBinSpot3"),
        AwsName::FBinSpot4 => f.write_str("FBinSpot4"),
        AwsName::FBinSpot5 => f.write_str("FBinSpot5"),
        AwsName::FBinSpot6 => f.write_str("FBinSpot6"),
        AwsName::FBinSpot7 => f.write_str("FBinSpot7"),
        AwsName::FBinSpot8 => f.write_str("FBinSpot8"),
        AwsName::FBinPerp => f.write_str("FBinPerp"),
        AwsName::FBinPerp2 => f.write_str("FBinPerp2"),
        AwsName::FOkexSpot => f.write_str("FOkexSpot"),
        AwsName::FOkexSpot2 => f.write_str("FOkexSpot2"),
        AwsName::FOkexPerp => f.write_str("FOkexPerp"),
        AwsName::FHuobiSpot => f.write_str("FHuobiSpot"),
        AwsName::FHuobiSpot2 => f.write_str("FHuobiSpot2"),
        AwsName::FHuobiSpot3 => f.write_str("FHuobiSpot3"),
        AwsName::FHuobiSpot4 => f.write_str("FHuobiSpot4"),
        AwsName::FHuobiPi => f.write_str("FHuobiPi"),
        AwsName::FHuobiPerp => f.write_str("FHuobiPerp"),
        AwsName::FCobSpot => f.write_str("FCobSpot"),
        AwsName::FKraSpot => f.write_str("FKraSpot"),
        AwsName::FBybitSpot => f.write_str("FBybitSpot"),
        AwsName::ScratchDummy => f.write_str("ScratchDummy"),
        AwsName::ScratchCron => f.write_str("ScratchCron"),
        AwsName::OBinSpot => f.write_str("OBinSpot"),
        AwsName::FHlPerp => f.write_str("FHlPerp"),
        AwsName::GaHlPerp => f.write_str("GaHlPerp"),
        AwsName::GaHlPerp2 => f.write_str("GaHlPerp2"),
        AwsName::GaHlPerp3 => f.write_str("GaHlPerp3"),
        AwsName::GbHlPerp => f.write_str("GbHlPerp"),
        AwsName::GbHlPerp2 => f.write_str("GbHlPerp2"),
        AwsName::GbHlPerp3 => f.write_str("GbHlPerp3"),
        AwsName::GcHlPerp => f.write_str("GcHlPerp"),
        AwsName::GcHlPerp2 => f.write_str("GcHlPerp2"),
        AwsName::GdHlPerp => f.write_str("GdHlPerp"),
        AwsName::GdHlPerp2 => f.write_str("GdHlPerp2"),
        AwsName::GsHlPerp => f.write_str("GsHlPerp"),
        AwsName::EaHlPerp => f.write_str("EaHlPerp"),
        AwsName::EbHlPerp => f.write_str("EbHlPerp"),
    }
}

/// Exact 663-byte node #115 `str::trim` (`0x1778840..0x1778ad7`).
#[inline(never)]
pub fn gc_str_trim(s: &str) -> &str {
    s.trim()
}

/// Exact 103-byte node #115 `cham_dir` create_dir_all panic helper (`0x1778270..0x17782d7`).
#[inline(never)]
pub fn gc_cham_dir_panic(cham_dir: &String, err: std::io::Error) -> ! {
    panic!("could not create {}: {:?}", *cham_dir, err);
}

#[inline(never)]
pub fn gc_drop_io_error_anchor(err: std::io::Error) {
    drop(err);
}

/// 0x50-byte `StaticConfig` layout matching node #115 `LazyLock<StaticConfig>` (`0x1774bf0`, `0x1774c80`).
pub struct StaticConfig {
    pub home_dir: String,
    pub cham_dir: String,
    pub code_dir: String,
    pub aws_name: AwsName,
}

#[inline(never)]
fn make_static_config() -> StaticConfig {
    StaticConfig {
        home_dir: String::new(),
        cham_dir: String::new(),
        code_dir: String::new(),
        aws_name: AwsName::NvTestnet,
    }
}

pub static STATIC_CONFIG: LazyLock<StaticConfig> = LazyLock::new(make_static_config);

#[inline(never)]
pub fn gc_get_static_config() -> &'static StaticConfig {
    &STATIC_CONFIG
}

/// Exact 25-byte `Visitor::expecting("variant identifier")` (`0x1774c60..0x1774c79`).
#[inline(never)]
pub fn gc_expecting_variant_identifier(_s: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("variant identifier")
}

/// Exact 25-byte `Visitor::expecting("VariantNotFound")` (`0x1774e40..0x1774e59`).
#[inline(never)]
pub fn gc_expecting_variant_not_found(_s: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("VariantNotFound")
}

/// Exact 25-byte `Visitor::expecting("unit")` (`0x17785b0..0x17785c9`).
#[inline(never)]
pub fn gc_expecting_unit(_s: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("unit")
}

/// Exact 20-byte `<String as Display>::fmt` thunk (`0x1772f80..0x1772f94` and `0x1777fb0..0x1777fc4`).
#[inline(never)]
pub fn gc_disp_string_thunk(s: &String, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.pad(s)
}

/// Exact 19-byte `<&str as Display>::fmt` thunk (`0x1778590..0x17785a3`).
#[inline(never)]
pub fn gc_disp_str_thunk(s: &&str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(s)
}
