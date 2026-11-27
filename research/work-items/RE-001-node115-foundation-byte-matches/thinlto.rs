#![forbid(unsafe_code)]

//! Independently authored node #115 `foundation` (`base`) ThinLTO crate-types,
//! `Debug` formatters, and `serde::de::Visitor::expecting` implementations
//! compiled under:
//! `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin -C codegen-units=1 -C save-temps`.
//!
//! Target: Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

use core::fmt;

/// Internal workspace crate enumeration observed at `0x1534270..0x153429f` (47 B).
#[derive(Debug)]
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

/// Phrase check error enumeration observed at `0x1544470..0x15444a3` (51 B).
#[derive(Debug)]
#[repr(u8)]
pub enum PhraseCheckError {
    ExpectedPhraseNotFound,
    UnexpectedPhraseFound,
}

/// Source code location observed across 8 FDEs (`0x1500880`, `0x1552430`, etc., 221 B each).
#[derive(Debug)]
pub struct CodeLocation {
    pub fln: &'static str,
    pub line: u32,
}

/// File compression options observed at `0x150cfe0..0x150d0bd` (221 B, `base/src/fu.rs`).
#[derive(Debug)]
pub struct ZipInnerArgs {
    pub silent: bool,
    pub remove_orig: bool,
}

#[derive(Debug)]
pub struct LockInner(pub [u64; 4]);

/// Lock identifier observed across 4 FDEs (`0x1544000`, etc., 224 B each, `base/src/lock_id.rs`).
#[derive(Debug)]
pub struct LockId {
    pub inner: LockInner,
    pub deadlock_detection: bool,
}

#[derive(Debug)]
pub struct LockIdAligned(pub [u128; 2]);

/// Lock acquisition site observed across 8 FDEs (`0x15440e0`, `0x1552350`, etc., 221 B each).
#[derive(Debug)]
pub struct LockLocation {
    pub id: LockIdAligned,
    pub call_location: CodeLocation,
}

/// Lock ordering witness observed across 4 FDEs (`0x15527d0`, etc., 221 B each).
#[derive(Debug)]
pub struct LockOrderWitness {
    pub a_lock_code_location: CodeLocation,
    pub b_lock_code_location: CodeLocation,
}

#[derive(Debug)]
pub struct ReverseEdge(pub [u64; 8]);

#[derive(Debug)]
pub struct ReverseWitness(pub [u64; 6]);

#[derive(Debug)]
pub struct LockRefA(pub [u64; 7]);

#[derive(Debug)]
pub struct LockRefB(pub u64);

/// Lock ordering violation payload observed across 4 FDEs (`0x15441c0`, etc., 165 B each).
#[derive(Debug)]
#[repr(C)]
pub struct LockOrderingViolation {
    pub reverse_edge: ReverseEdge,
    pub reverse_witness: ReverseWitness,
    pub lock_a: LockRefA,
    pub lock_b: LockRefB,
}

#[derive(Debug)]
pub struct U256Stub(pub [u64; 4]);

/// ECDSA signature (`r`, `s`, `v`) observed across 5 FDEs (`0x1534160` 263 B + 4x 260 B).
#[derive(Debug)]
pub struct Signature {
    pub r: U256Stub,
    pub s: U256Stub,
    pub v: u64,
}

#[derive(Debug)]
#[repr(u8)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

/// Logger settings observed at `0x1544270..0x154446c` (508 B) and `0x15528b0..0x1552aa9` (505 B).
#[derive(Debug)]
pub struct LogSettings {
    pub level: LogLevel,
    pub err_fln: String,
    pub stdout_fln: String,
    pub throttle: bool,
    pub log_to_stdout: bool,
    pub n_overflow_files: u32,
    pub custom_dir: Option<String>,
}

#[inline(never)]
pub fn fmt_crate_debug_ref(v: &&Crate, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&Crate as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_phrase_err_debug_ref(v: &&PhraseCheckError, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&PhraseCheckError as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_code_location_ref(v: &&CodeLocation, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&CodeLocation as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_code_location(v: &CodeLocation, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <CodeLocation as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_zip_inner_args(v: &ZipInnerArgs, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <ZipInnerArgs as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_lock_id_refref(v: &&&LockId, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&&LockId as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_lock_location_ref(v: &&LockLocation, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&LockLocation as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_lock_location(v: &LockLocation, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <LockLocation as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_lock_order_witness(v: &LockOrderWitness, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <LockOrderWitness as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_lock_ordering_violation_ref(
    v: &&LockOrderingViolation,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    <&LockOrderingViolation as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_signature_refref(v: &&&Signature, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&&Signature as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_signature_ref(v: &&Signature, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&Signature as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_signature(v: &Signature, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <Signature as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_log_settings_ref(v: &&LogSettings, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&LogSettings as fmt::Debug>::fmt(v, f)
}

#[inline(never)]
pub fn fmt_log_settings(v: &LogSettings, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <LogSettings as fmt::Debug>::fmt(v, f)
}

macro_rules! def_expecting {
    ($( ($name:ident, $msg:literal) ),+ $(,)?) => {
        $(
            #[inline(never)]
            pub fn $name(_v: &u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($msg)
            }
        )+
    };
}

def_expecting!(
    (base_expecting_bug_alert_ack, "struct BugAlertAck"),
    (base_expecting_ignore, "struct Ignore"),
    (base_expecting_signature, "struct Signature"),
    (base_expecting_tuple_time, "tuple struct Time"),
    (base_expecting_api_secrets, "struct ApiSecrets"),
    (
        base_expecting_signed_indexed_upload,
        "struct SignedIndexedUpload"
    ),
    (base_expecting_visor_metadata, "struct VisorMetadata"),
    (base_expecting_hotfix_args, "struct HotfixArgs"),
    (base_expecting_hotfix_metadata, "struct HotfixMetadata"),
    (
        base_expecting_publisher_binary_metadata,
        "struct PublisherBinaryMetadata"
    ),
    (
        base_expecting_tuple_bucket_guard,
        "tuple struct BucketGuard"
    ),
    (base_expecting_struct_bucket_guard, "struct BucketGuard"),
);

fn main() {
    let keep: [*const (); 27] = [
        fmt_crate_debug_ref as *const (),
        fmt_phrase_err_debug_ref as *const (),
        fmt_code_location_ref as *const (),
        fmt_code_location as *const (),
        fmt_zip_inner_args as *const (),
        fmt_lock_id_refref as *const (),
        fmt_lock_location_ref as *const (),
        fmt_lock_location as *const (),
        fmt_lock_order_witness as *const (),
        fmt_lock_ordering_violation_ref as *const (),
        fmt_signature_refref as *const (),
        fmt_signature_ref as *const (),
        fmt_signature as *const (),
        fmt_log_settings_ref as *const (),
        fmt_log_settings as *const (),
        base_expecting_bug_alert_ack as *const (),
        base_expecting_ignore as *const (),
        base_expecting_signature as *const (),
        base_expecting_tuple_time as *const (),
        base_expecting_api_secrets as *const (),
        base_expecting_signed_indexed_upload as *const (),
        base_expecting_visor_metadata as *const (),
        base_expecting_hotfix_args as *const (),
        base_expecting_hotfix_metadata as *const (),
        base_expecting_publisher_binary_metadata as *const (),
        base_expecting_tuple_bucket_guard as *const (),
        base_expecting_struct_bucket_guard as *const (),
    ];
    std::hint::black_box(keep);
}
