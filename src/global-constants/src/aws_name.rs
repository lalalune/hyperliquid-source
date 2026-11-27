//! Node #115 `global_constants/src/aws_name.rs` reconstruction.
//!
//! All 79 variant names and discriminants (`0..=78`) are bound directly to
//! node #115 `.data.rel.ro` pointer/length arrays at `0x63f8788` and
//! `0x6410ce8`, plain classifier `0x1775500`, serde classifier `0x1774100`,
//! and formatter `0x1774e60` (jump table `0x481bd0`).

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;

/// Error returned when parsing an unknown `AwsName` spelling.
///
/// Matches the `VariantNotFound` debug formatter at node #115 VA `0x1774e40`
/// (string literal at `0x481fb5`).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VariantNotFound;

impl fmt::Debug for VariantNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VariantNotFound")
    }
}

impl fmt::Display for VariantNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VariantNotFound")
    }
}

impl std::error::Error for VariantNotFound {}

/// Error returned by the non-panicking [`AwsName::try_read_from_file`] helper.
#[derive(Debug)]
pub enum AwsNameFileError {
    Io(io::Error),
    Parse(VariantNotFound),
}

impl fmt::Display for AwsNameFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read aws_name file: {err}"),
            Self::Parse(err) => write!(f, "failed to parse aws_name file: {err}"),
        }
    }
}

impl std::error::Error for AwsNameFileError {}

/// Complete 79-variant `AwsName` enum in exact node #115 discriminant order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

impl AwsName {
    /// Total number of valid discriminants (`0..79`), matching `.rodata` bound
    /// diagnostic `variant index 0 <= i < 79` at `0x464893`.
    pub const COUNT: usize = 79;

    /// Sentinel byte written for unknown/missing values in the target's plain
    /// classifier (`0x1775500`) and struct visitor (`0x17771b0`).
    pub const UNKNOWN_SENTINEL: u8 = 79;

    /// Fallback returned by `read_aws_name` (`0x17783e0`, `mov $0x21, %bpl` at
    /// `0x177845c`) when reading or parsing `{code_dir}/static_config` fails.
    pub const DEFAULT_FALLBACK: Self = Self::NvTestnet;

    /// All 79 variants in discriminant order `0..=78`.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Ec,
        Self::DummyTokyo,
        Self::DummyTokyo2,
        Self::GaOnchain,
        Self::GbOnchain,
        Self::NodeTestnet,
        Self::NodeTestnet2,
        Self::NodeTestnet3,
        Self::NodeTestnet4,
        Self::Ea,
        Self::Ea2,
        Self::Ea3,
        Self::EaMm,
        Self::EaTx,
        Self::HeavyTestnet,
        Self::HeavyMainnet,
        Self::Eb,
        Self::Ed,
        Self::Ee,
        Self::SoloTestnet,
        Self::SoloMainnet,
        Self::LockerTestnet,
        Self::LockerMainnet,
        Self::RpcTestnet,
        Self::RpcSandbox,
        Self::RpcMainnet,
        Self::RpcMainnet2,
        Self::Sa,
        Self::Sb,
        Self::Sc,
        Self::Sd,
        Self::WebSandbox,
        Self::SoloSandbox,
        Self::NvTestnet,
        Self::NvTestnet2,
        Self::NvMainnet,
        Self::NvMainnet2,
        Self::NvMainnet3,
        Self::JoinMainnet,
        Self::DummyNv,
        Self::FBinSpot,
        Self::FBinSpot2,
        Self::FBinSpot3,
        Self::FBinSpot4,
        Self::FBinSpot5,
        Self::FBinSpot6,
        Self::FBinSpot7,
        Self::FBinSpot8,
        Self::FBinPerp,
        Self::FBinPerp2,
        Self::FOkexSpot,
        Self::FOkexSpot2,
        Self::FOkexPerp,
        Self::FHuobiSpot,
        Self::FHuobiSpot2,
        Self::FHuobiSpot3,
        Self::FHuobiSpot4,
        Self::FHuobiPi,
        Self::FHuobiPerp,
        Self::FCobSpot,
        Self::FKraSpot,
        Self::FBybitSpot,
        Self::ScratchDummy,
        Self::ScratchCron,
        Self::OBinSpot,
        Self::FHlPerp,
        Self::GaHlPerp,
        Self::GaHlPerp2,
        Self::GaHlPerp3,
        Self::GbHlPerp,
        Self::GbHlPerp2,
        Self::GbHlPerp3,
        Self::GcHlPerp,
        Self::GcHlPerp2,
        Self::GdHlPerp,
        Self::GdHlPerp2,
        Self::GsHlPerp,
        Self::EaHlPerp,
        Self::EbHlPerp,
    ];

    /// Bitmask observed at `STATIC_CONFIG.aws_name` call sites (`0x2a35c66`..,
    /// `0x4fbd23d`..): `cmp rax, 0x20; bt 0x10078c000, rax`.
    /// Selects `{HeavyTestnet(14), HeavyMainnet(15), SoloTestnet(19),
    /// SoloMainnet(20), LockerTestnet(21), LockerMainnet(22), SoloSandbox(32)}`.
    pub const SOLO_HEAVY_LOCKER_MASK: u64 = 0x1_0078_c000;

    #[inline]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_discriminant(byte: u8) -> Option<Self> {
        if (byte as usize) < Self::COUNT {
            Some(Self::ALL[byte as usize])
        } else {
            None
        }
    }

    /// Exact wire/display spelling matching `0x1774e60` and tables `0x63f8788` / `0x6410ce8`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ec => "Ec",
            Self::DummyTokyo => "DummyTokyo",
            Self::DummyTokyo2 => "DummyTokyo2",
            Self::GaOnchain => "GaOnchain",
            Self::GbOnchain => "GbOnchain",
            Self::NodeTestnet => "NodeTestnet",
            Self::NodeTestnet2 => "NodeTestnet2",
            Self::NodeTestnet3 => "NodeTestnet3",
            Self::NodeTestnet4 => "NodeTestnet4",
            Self::Ea => "Ea",
            Self::Ea2 => "Ea2",
            Self::Ea3 => "Ea3",
            Self::EaMm => "EaMm",
            Self::EaTx => "EaTx",
            Self::HeavyTestnet => "HeavyTestnet",
            Self::HeavyMainnet => "HeavyMainnet",
            Self::Eb => "Eb",
            Self::Ed => "Ed",
            Self::Ee => "Ee",
            Self::SoloTestnet => "SoloTestnet",
            Self::SoloMainnet => "SoloMainnet",
            Self::LockerTestnet => "LockerTestnet",
            Self::LockerMainnet => "LockerMainnet",
            Self::RpcTestnet => "RpcTestnet",
            Self::RpcSandbox => "RpcSandbox",
            Self::RpcMainnet => "RpcMainnet",
            Self::RpcMainnet2 => "RpcMainnet2",
            Self::Sa => "Sa",
            Self::Sb => "Sb",
            Self::Sc => "Sc",
            Self::Sd => "Sd",
            Self::WebSandbox => "WebSandbox",
            Self::SoloSandbox => "SoloSandbox",
            Self::NvTestnet => "NvTestnet",
            Self::NvTestnet2 => "NvTestnet2",
            Self::NvMainnet => "NvMainnet",
            Self::NvMainnet2 => "NvMainnet2",
            Self::NvMainnet3 => "NvMainnet3",
            Self::JoinMainnet => "JoinMainnet",
            Self::DummyNv => "DummyNv",
            Self::FBinSpot => "FBinSpot",
            Self::FBinSpot2 => "FBinSpot2",
            Self::FBinSpot3 => "FBinSpot3",
            Self::FBinSpot4 => "FBinSpot4",
            Self::FBinSpot5 => "FBinSpot5",
            Self::FBinSpot6 => "FBinSpot6",
            Self::FBinSpot7 => "FBinSpot7",
            Self::FBinSpot8 => "FBinSpot8",
            Self::FBinPerp => "FBinPerp",
            Self::FBinPerp2 => "FBinPerp2",
            Self::FOkexSpot => "FOkexSpot",
            Self::FOkexSpot2 => "FOkexSpot2",
            Self::FOkexPerp => "FOkexPerp",
            Self::FHuobiSpot => "FHuobiSpot",
            Self::FHuobiSpot2 => "FHuobiSpot2",
            Self::FHuobiSpot3 => "FHuobiSpot3",
            Self::FHuobiSpot4 => "FHuobiSpot4",
            Self::FHuobiPi => "FHuobiPi",
            Self::FHuobiPerp => "FHuobiPerp",
            Self::FCobSpot => "FCobSpot",
            Self::FKraSpot => "FKraSpot",
            Self::FBybitSpot => "FBybitSpot",
            Self::ScratchDummy => "ScratchDummy",
            Self::ScratchCron => "ScratchCron",
            Self::OBinSpot => "OBinSpot",
            Self::FHlPerp => "FHlPerp",
            Self::GaHlPerp => "GaHlPerp",
            Self::GaHlPerp2 => "GaHlPerp2",
            Self::GaHlPerp3 => "GaHlPerp3",
            Self::GbHlPerp => "GbHlPerp",
            Self::GbHlPerp2 => "GbHlPerp2",
            Self::GbHlPerp3 => "GbHlPerp3",
            Self::GcHlPerp => "GcHlPerp",
            Self::GcHlPerp2 => "GcHlPerp2",
            Self::GdHlPerp => "GdHlPerp",
            Self::GdHlPerp2 => "GdHlPerp2",
            Self::GsHlPerp => "GsHlPerp",
            Self::EaHlPerp => "EaHlPerp",
            Self::EbHlPerp => "EbHlPerp",
        }
    }

    /// Plain classifier matching `0x1775500` (returns `79` on unknown spelling).
    pub fn classify_byte(s: &str) -> u8 {
        match Self::from_str(s) {
            Ok(variant) => variant.discriminant(),
            Err(_) => Self::UNKNOWN_SENTINEL,
        }
    }

    /// Trim Unicode `White_Space` (matching `0x1778840`) and parse as `AwsName`.
    pub fn from_trimmed_str(s: &str) -> Result<Self, VariantNotFound> {
        Self::from_str(s.trim())
    }

    /// Non-panicking reader for `{cham_dir}/aws_name`.
    pub fn try_read_from_file(path: &Path) -> Result<Self, AwsNameFileError> {
        let raw = fs::read_to_string(path).map_err(AwsNameFileError::Io)?;
        Self::from_trimmed_str(&raw).map_err(AwsNameFileError::Parse)
    }

    /// Panicking missing-name fallback reader matching `0x1773fd0`
    /// (`aws_name.rs:295:44` read unwrap and `aws_name.rs:295:68` parse unwrap).
    pub fn read_from_file(path: &Path) -> Self {
        let raw = fs::read_to_string(path).unwrap();
        Self::from_trimmed_str(&raw).unwrap()
    }

    /// 79-entry `f64` lookup table observed at `.rodata` VA `0x4671d0`
    /// (loaded by `0x15474e7` via `STATIC_CONFIG.aws_name`):
    /// `1.0` for the 18 mainnet/Tokyo/Ea variants, `5.0` for all 61 others.
    pub const fn rodata_4671d0_f64(self) -> f64 {
        match self {
            Self::DummyTokyo
            | Self::DummyTokyo2
            | Self::Ea
            | Self::Ea2
            | Self::Ea3
            | Self::EaMm
            | Self::EaTx
            | Self::HeavyMainnet
            | Self::Eb
            | Self::Ee
            | Self::SoloMainnet
            | Self::LockerMainnet
            | Self::RpcMainnet
            | Self::RpcMainnet2
            | Self::NvMainnet
            | Self::NvMainnet2
            | Self::NvMainnet3
            | Self::JoinMainnet => 1.0,
            _ => 5.0,
        }
    }

    /// Observed bitmask predicate (`cmp rax, 0x20; bt 0x10078c000, rax`).
    #[inline]
    pub const fn is_solo_heavy_or_locker(self) -> bool {
        self.matches_bitmask(0x20, Self::SOLO_HEAVY_LOCKER_MASK)
    }

    /// Helper matching LLVM's `cmp reg, max; ja false; bt mask, reg` pattern
    /// used across `STATIC_CONFIG.aws_name` call sites.
    #[inline]
    pub const fn matches_bitmask(self, max_inclusive: u8, mask: u64) -> bool {
        let idx = self as u8;
        idx <= max_inclusive && idx < 64 && ((mask >> idx) & 1) != 0
    }

    /// Guard observed inlined at `0x2e12c68` and `0x2e12fde` (`global_constants/src/aws_name.rs:213:29`,
    /// inside validator-pair disconnect alerting `0x2e11b00..0x2e13c3a`): panics with
    /// `unimplemented!()` (`"not implemented"` at `.rodata` `0x481f69`) when called for
    /// `ChainName::Local` (discriminant `0`), and succeeds for `Sandbox`, `Testnet`, and `Mainnet`.
    pub fn assert_non_local_chain(chain: node115_chain_name_codec::ChainName) {
        if chain == node115_chain_name_codec::ChainName::Local {
            unimplemented!();
        }
    }
}

impl fmt::Display for AwsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AwsName {
    type Err = VariantNotFound;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Length gate `len - 2 <= 11` matching jump table 0x481d0c (lengths 2..=13).
        if !(2..=13).contains(&s.len()) {
            return Err(VariantNotFound);
        }
        match s {
            "Ec" => Ok(Self::Ec),
            "DummyTokyo" => Ok(Self::DummyTokyo),
            "DummyTokyo2" => Ok(Self::DummyTokyo2),
            "GaOnchain" => Ok(Self::GaOnchain),
            "GbOnchain" => Ok(Self::GbOnchain),
            "NodeTestnet" => Ok(Self::NodeTestnet),
            "NodeTestnet2" => Ok(Self::NodeTestnet2),
            "NodeTestnet3" => Ok(Self::NodeTestnet3),
            "NodeTestnet4" => Ok(Self::NodeTestnet4),
            "Ea" => Ok(Self::Ea),
            "Ea2" => Ok(Self::Ea2),
            "Ea3" => Ok(Self::Ea3),
            "EaMm" => Ok(Self::EaMm),
            "EaTx" => Ok(Self::EaTx),
            "HeavyTestnet" => Ok(Self::HeavyTestnet),
            "HeavyMainnet" => Ok(Self::HeavyMainnet),
            "Eb" => Ok(Self::Eb),
            "Ed" => Ok(Self::Ed),
            "Ee" => Ok(Self::Ee),
            "SoloTestnet" => Ok(Self::SoloTestnet),
            "SoloMainnet" => Ok(Self::SoloMainnet),
            "LockerTestnet" => Ok(Self::LockerTestnet),
            "LockerMainnet" => Ok(Self::LockerMainnet),
            "RpcTestnet" => Ok(Self::RpcTestnet),
            "RpcSandbox" => Ok(Self::RpcSandbox),
            "RpcMainnet" => Ok(Self::RpcMainnet),
            "RpcMainnet2" => Ok(Self::RpcMainnet2),
            "Sa" => Ok(Self::Sa),
            "Sb" => Ok(Self::Sb),
            "Sc" => Ok(Self::Sc),
            "Sd" => Ok(Self::Sd),
            "WebSandbox" => Ok(Self::WebSandbox),
            "SoloSandbox" => Ok(Self::SoloSandbox),
            "NvTestnet" => Ok(Self::NvTestnet),
            "NvTestnet2" => Ok(Self::NvTestnet2),
            "NvMainnet" => Ok(Self::NvMainnet),
            "NvMainnet2" => Ok(Self::NvMainnet2),
            "NvMainnet3" => Ok(Self::NvMainnet3),
            "JoinMainnet" => Ok(Self::JoinMainnet),
            "DummyNv" => Ok(Self::DummyNv),
            "FBinSpot" => Ok(Self::FBinSpot),
            "FBinSpot2" => Ok(Self::FBinSpot2),
            "FBinSpot3" => Ok(Self::FBinSpot3),
            "FBinSpot4" => Ok(Self::FBinSpot4),
            "FBinSpot5" => Ok(Self::FBinSpot5),
            "FBinSpot6" => Ok(Self::FBinSpot6),
            "FBinSpot7" => Ok(Self::FBinSpot7),
            "FBinSpot8" => Ok(Self::FBinSpot8),
            "FBinPerp" => Ok(Self::FBinPerp),
            "FBinPerp2" => Ok(Self::FBinPerp2),
            "FOkexSpot" => Ok(Self::FOkexSpot),
            "FOkexSpot2" => Ok(Self::FOkexSpot2),
            "FOkexPerp" => Ok(Self::FOkexPerp),
            "FHuobiSpot" => Ok(Self::FHuobiSpot),
            "FHuobiSpot2" => Ok(Self::FHuobiSpot2),
            "FHuobiSpot3" => Ok(Self::FHuobiSpot3),
            "FHuobiSpot4" => Ok(Self::FHuobiSpot4),
            "FHuobiPi" => Ok(Self::FHuobiPi),
            "FHuobiPerp" => Ok(Self::FHuobiPerp),
            "FCobSpot" => Ok(Self::FCobSpot),
            "FKraSpot" => Ok(Self::FKraSpot),
            "FBybitSpot" => Ok(Self::FBybitSpot),
            "ScratchDummy" => Ok(Self::ScratchDummy),
            "ScratchCron" => Ok(Self::ScratchCron),
            "OBinSpot" => Ok(Self::OBinSpot),
            "FHlPerp" => Ok(Self::FHlPerp),
            "GaHlPerp" => Ok(Self::GaHlPerp),
            "GaHlPerp2" => Ok(Self::GaHlPerp2),
            "GaHlPerp3" => Ok(Self::GaHlPerp3),
            "GbHlPerp" => Ok(Self::GbHlPerp),
            "GbHlPerp2" => Ok(Self::GbHlPerp2),
            "GbHlPerp3" => Ok(Self::GbHlPerp3),
            "GcHlPerp" => Ok(Self::GcHlPerp),
            "GcHlPerp2" => Ok(Self::GcHlPerp2),
            "GdHlPerp" => Ok(Self::GdHlPerp),
            "GdHlPerp2" => Ok(Self::GdHlPerp2),
            "GsHlPerp" => Ok(Self::GsHlPerp),
            "EaHlPerp" => Ok(Self::EaHlPerp),
            "EbHlPerp" => Ok(Self::EbHlPerp),
            _ => Err(VariantNotFound),
        }
    }
}
