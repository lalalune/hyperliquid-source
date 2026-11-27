//! First-party `base` diagnostic, logging, and metadata types whose exact field
//! layouts and `Debug` formatters are verified to 100.00% relocation-qualified
//! compiled-byte identity against node #115.

/// Internal workspace crate enum (`0x1534270..0x153429f`, 47 B, 13 variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Crate {
    Base,
    PeriBase,
    Infra,
    Live,
    Nexus,
    Trade,
    Nn,
    L1,
    Node,
    Peripheral,
    NetUtils,
    Db,
    EvmRpc,
}

impl Crate {
    pub const ALL: [Self; 13] = [
        Self::Base,
        Self::PeriBase,
        Self::Infra,
        Self::Live,
        Self::Nexus,
        Self::Trade,
        Self::Nn,
        Self::L1,
        Self::Node,
        Self::Peripheral,
        Self::NetUtils,
        Self::Db,
        Self::EvmRpc,
    ];
}

/// Phrase check error enum (`0x1544470..0x15444a3`, 51 B).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PhraseCheckError {
    ExpectedPhraseNotFound,
    UnexpectedPhraseFound,
}

/// File compression arguments (`0x150cfe0..0x150d0bd`, 221 B, `base/src/fu.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZipInnerArgs {
    pub silent: bool,
    pub remove_orig: bool,
}

/// Logger verbosity level for [`LogSettings`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

/// Logger configuration (`0x1544270..0x154446c` 508 B & `0x15528b0..0x1552aa9` 505 B).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogSettings {
    pub level: LogLevel,
    pub err_fln: String,
    pub stdout_fln: String,
    pub throttle: bool,
    pub log_to_stdout: bool,
    pub n_overflow_files: u32,
    pub custom_dir: Option<String>,
}

/// ECDSA signature (`r`, `s`, `v`) matching `0x1534160` (263 B) + 4x 260 B `Debug` FDEs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    pub r: [u64; 4],
    pub s: [u64; 4],
    pub v: u64,
}
