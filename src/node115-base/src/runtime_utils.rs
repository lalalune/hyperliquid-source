//! Runtime utilities covering the remaining node #115 `base/src/*.rs` files:
//! `api_secrets`, `chain_ext`, `crit_msg`, `curl`, `daily_liner`, `data_cache`,
//! `file_mod_time_tracker`, `fodname`, `fu`, `http_client`, `lazy_mutex`, `liner`,
//! `log/{handle,state}`, `lu`, `production`, `quorum_policy`, `ren`, `shell`,
//! `slack_alert`, `u`, and `wallet`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::log_settings::LogSettings;

/// Redacted API secrets container (`base/src/api_secrets.rs`).
#[derive(Clone, PartialEq, Eq)]
pub struct ApiSecrets {
    keys: BTreeMap<String, String>,
}

impl ApiSecrets {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Result<(), &'static str> {
        let k = name.into();
        let v = value.into();
        if k.is_empty() || v.is_empty() {
            return Err("secret key and value must be non-empty");
        }
        self.keys.insert(k, v);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.keys.get(name).map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for ApiSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ApiSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiSecrets")
            .field("keys", &self.keys.len())
            .finish()
    }
}

/// Chain network identity extension (`base/src/chain_ext.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainKind {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

impl ChainKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::Sandbox => "Sandbox",
            Self::Testnet => "Testnet",
            Self::Mainnet => "Mainnet",
        }
    }

    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Mainnet | Self::Testnet)
    }
}

/// Critical alert and Slack rate-limiter (`base/src/crit_msg.rs`, `base/src/slack_alert.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertSeverity {
    Warn,
    Error,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CritAlert {
    pub severity: AlertSeverity,
    pub tag: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct SlackAlertThrottle {
    min_interval_ms: u64,
    last_sent_ms: BTreeMap<String, u64>,
}

impl SlackAlertThrottle {
    #[must_use]
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval_ms,
            last_sent_ms: BTreeMap::new(),
        }
    }

    pub fn should_send(&mut self, tag: &str, now_ms: u64) -> bool {
        if self
            .last_sent_ms
            .get(tag)
            .is_some_and(|&prev| now_ms.saturating_sub(prev) < self.min_interval_ms)
        {
            return false;
        }
        self.last_sent_ms.insert(tag.to_owned(), now_ms);
        true
    }
}

/// Offline-safe HTTP/cURL request specification (`base/src/curl.rs`, `base/src/http_client.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestSpec {
    pub method: String,
    pub url: String,
    pub timeout_ms: u64,
    pub headers: BTreeMap<String, String>,
}

impl HttpRequestSpec {
    pub fn new(method: impl Into<String>, url: impl Into<String>, timeout_ms: u64) -> Result<Self, &'static str> {
        let method = method.into();
        let url = url.into();
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err("invalid HTTP(S) URL scheme");
        }
        if timeout_ms == 0 {
            return Err("timeout_ms must be positive");
        }
        Ok(Self {
            method,
            url,
            timeout_ms,
            headers: BTreeMap::new(),
        })
    }
}

/// Line-oriented append buffer and UTC-day rotated log path (`base/src/liner.rs`, `base/src/daily_liner.rs`).
#[derive(Clone, Debug, Default)]
pub struct LinerBuffer {
    lines: Vec<String>,
}

impl LinerBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_line(&mut self, line: impl Into<String>) -> Result<(), &'static str> {
        let s = line.into();
        if s.contains('\n') {
            return Err("line must not contain embedded newline");
        }
        self.lines.push(s);
        Ok(())
    }

    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// A day or hour in a registered stream directory (`0x1546570..0x15466f3`).
/// The date is the writer's already-formatted `%Y%m%d` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinerBucket<'a> {
    date: &'a str,
    hour: Option<u8>,
}

impl<'a> LinerBucket<'a> {
    pub fn daily(date: &'a str) -> Self {
        Self { date, hour: None }
    }

    pub fn hourly(date: &'a str, seconds_of_day: u32) -> Result<Self, crate::time::HourDecodeError> {
        let hour = crate::time::hour_from_secs_of_day(seconds_of_day)?;
        Ok(Self { date, hour: Some(hour) })
    }

    /// Select a new path when the writer changes date or, in hourly mode, hour.
    /// Supply the bucket of the last successfully opened file as `previous`.
    #[must_use]
    pub fn path_if_changed(self, directory: &Path, previous: Option<Self>) -> Option<PathBuf> {
        (Some(self) != previous).then(|| self.path(directory))
    }

    #[must_use]
    pub fn path(self, directory: &Path) -> PathBuf {
        match self.hour {
            Some(hour) => directory.join("hourly").join(self.date).join(hour.to_string()),
            None => directory.join(self.date),
        }
    }
}

/// Path for a daily stream under an already-resolved data root and registered name.
#[must_use]
pub fn daily_liner_path(data_root: &Path, yyyymmdd: &str, name: &str) -> PathBuf {
    LinerBucket::daily(yyyymmdd).path(&data_root.join(name))
}

/// Bounded generation/TTL cache (`base/src/data_cache.rs`).
#[derive(Clone, Debug)]
pub struct DataCache<K, V> {
    ttl_ms: u64,
    entries: BTreeMap<K, (u64, V)>,
}

impl<K: Ord, V> DataCache<K, V> {
    #[must_use]
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: K, value: V, now_ms: u64) {
        self.entries.insert(key, (now_ms, value));
    }

    #[must_use]
    pub fn get_fresh(&self, key: &K, now_ms: u64) -> Option<&V> {
        let (ts, val) = self.entries.get(key)?;
        if now_ms.saturating_sub(*ts) <= self.ttl_ms {
            Some(val)
        } else {
            None
        }
    }
}

/// File modification-time change tracker (`base/src/file_mod_time_tracker.rs`).
#[derive(Clone, Debug, Default)]
pub struct FileModTimeTracker {
    last_mtime_ns: Option<u128>,
}

impl FileModTimeTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self { last_mtime_ns: None }
    }

    pub fn observe(&mut self, mtime_ns: u128) -> bool {
        if self.last_mtime_ns == Some(mtime_ns) {
            return false;
        }
        self.last_mtime_ns = Some(mtime_ns);
        true
    }
}

/// Formatted date/hour/name path helper (`base/src/fodname.rs`).
#[must_use]
pub fn fodname(base_dir: &Path, date_yyyymmdd: &str, hour: u8, stem: &str) -> Option<PathBuf> {
    if hour >= 24 || date_yyyymmdd.len() != 8 || !date_yyyymmdd.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(base_dir.join(date_yyyymmdd).join(format!("{hour}")).join(stem))
}

/// File/path, log, rename, and general utilities (`base/src/{fu,lu,ren,u}.rs`).
#[must_use]
pub fn sanitize_rel_segment(seg: &str) -> Option<&str> {
    if seg.is_empty() || seg == "." || seg == ".." || seg.contains('/') || seg.contains('\0') {
        None
    } else {
        Some(seg)
    }
}

#[must_use]
pub fn staging_rename_path(target: &Path, nonce: u64) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_owned());
    name.push_str(&format!(".tmp.{nonce}"));
    target.with_file_name(name)
}

#[must_use]
pub fn format_log_prefix(tag: &str, level: &str) -> String {
    format!("[{level}][{tag}]")
}

/// Lazy initialized mutex wrapper (`base/src/lazy_mutex.rs`).
pub struct LazyMutex<T> {
    cell: OnceLock<Mutex<T>>,
}

impl<T> LazyMutex<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    pub fn lock_or_init(&self, init: impl FnOnce() -> T) -> MutexGuard<'_, T> {
        self.cell
            .get_or_init(|| Mutex::new(init()))
            .lock()
            .expect("LazyMutex poisoned")
    }
}

impl<T> Default for LazyMutex<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Logging handle and state container (`base/src/log/{handle,state}.rs`).
#[derive(Clone, Debug)]
pub struct LogState {
    pub settings: LogSettings,
    pub overflow_count: usize,
}

#[derive(Clone, Debug)]
pub struct LogHandle {
    state: LogState,
}

impl LogHandle {
    #[must_use]
    pub fn new(settings: LogSettings) -> Self {
        Self {
            state: LogState {
                settings,
                overflow_count: 0,
            },
        }
    }

    #[must_use]
    pub fn state(&self) -> &LogState {
        &self.state
    }
}

/// Production-mode safety guard (`base/src/production.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionGuard {
    pub chain: ChainKind,
    pub allow_unsafe_test_overrides: bool,
}

impl ProductionGuard {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain.is_production() && self.allow_unsafe_test_overrides {
            return Err("unsafe test overrides forbidden in production");
        }
        Ok(())
    }
}

/// Strict supermajority quorum policy (`base/src/quorum_policy.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumPolicy {
    pub numerator: u128,
    pub denominator: u128,
}

impl QuorumPolicy {
    pub const TWO_THIRDS: Self = Self {
        numerator: 2,
        denominator: 3,
    };

    #[must_use]
    pub fn has_strict_quorum(self, stake: u128, total_stake: u128) -> bool {
        if total_stake == 0 || self.denominator == 0 {
            return false;
        }
        stake
            .checked_mul(self.denominator)
            .zip(total_stake.checked_mul(self.numerator))
            .is_some_and(|(lhs, rhs)| lhs > rhs)
    }
}

/// Sanitized shell command specification (`base/src/shell.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl ShellSpec {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Result<Self, &'static str> {
        let program = program.into();
        if program.is_empty() || program.contains('\0') {
            return Err("invalid shell program");
        }
        if args.iter().any(|a| a.contains('\0')) {
            return Err("NUL byte in shell arg");
        }
        Ok(Self { program, args })
    }
}

/// 20-byte wallet address parser and hex formatter (`base/src/wallet.rs`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletAddress(pub [u8; 20]);

impl WalletAddress {
    pub fn parse_hex(input: &str) -> Result<Self, &'static str> {
        let hex = input.strip_prefix("0x").ok_or("missing 0x prefix")?;
        if hex.len() != 40 {
            return Err("wallet address must be 40 hex chars");
        }
        let mut out = [0u8; 20];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| "invalid hex nibble")?;
        }
        Ok(Self(out))
    }

    #[must_use]
    pub fn to_hex_lower(self) -> String {
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for b in self.0 {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }
}

impl fmt::Debug for WalletAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex_lower())
    }
}
