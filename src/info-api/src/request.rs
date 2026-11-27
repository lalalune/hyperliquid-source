//! Complete 55-variant `InfoRequest` and 2-variant `FileSnapshotRequest` wire schemas
//! recovered statically from node #115:
//! - `.data.rel.ro` `0x643a9e0..0x643ad50` (55 `InfoRequest` variant names)
//! - `0x2744200..0x2744bfa` (`InfoRequest` serde variant matcher, `mov ecx, 0x37`)
//! - `0x273bf30..0x273ebc0` (`InfoRequest` internally tagged `type` serializer, jump table `0x5f45d0`)
//! - `.data.rel.ro` `0x643ad50..0x643ad70` (2 `FileSnapshotRequest` variant names)

use node115_json_error_position::position as json_error_position;
use node115_json_string_scanner::{scan as scan_json_string, Output as ScanOutput};

/// Tag key used by internally-tagged `InfoRequest` JSON objects (`0x45a144` in `0x273bf30`).
pub const INFO_REQUEST_TAG_KEY: &str = "type";

/// Exact variant count of `InfoRequest` in node #115 (`0x37` = 55).
pub const INFO_REQUEST_VARIANT_COUNT: usize = 55;

/// All 55 `InfoRequest` variants in exact node #115 discriminant order (`0..=54`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InfoRequestKind {
    FileSnapshot = 0,
    WebData2 = 1,
    WebData3 = 2,
    Meta = 3,
    SpotMeta = 4,
    OutcomeMeta = 5,
    OutcomeDeployerLimits = 6,
    ClearinghouseState = 7,
    SpotClearinghouseState = 8,
    OpenOrders = 9,
    ExchangeStatus = 10,
    FrontendOpenOrders = 11,
    ActiveAssetData = 12,
    MaxMarketOrderNtls = 13,
    VaultSummaries = 14,
    UserVaultEquities = 15,
    LeadingVaults = 16,
    ExtraAgents = 17,
    SubAccounts = 18,
    SubAccounts2 = 19,
    UserFees = 20,
    UserRateLimit = 21,
    SpotDeployState = 22,
    SpotPairDeployAuctionStatus = 23,
    PerpDeployAuctionStatus = 24,
    Votes = 25,
    Delegations = 26,
    DelegatorSummary = 27,
    MaxBuilderFee = 28,
    UserToMultiSigSigners = 29,
    UserRole = 30,
    PerpsAtOpenInterestCap = 31,
    PerpDexLimits = 32,
    ValidatorL1Votes = 33,
    MarginTable = 34,
    PerpDexs = 35,
    AllPerpMetas = 36,
    UserDexAbstraction = 37,
    PerpDexStatus = 38,
    BorrowLendUserState = 39,
    BorrowLendReserveState = 40,
    AllBorrowLendReserveStates = 41,
    UserAbstraction = 42,
    PerpAnnotation = 43,
    PerpCategories = 44,
    PerpConciseAnnotations = 45,
    TokenAnnotation = 46,
    TokenConciseAnnotations = 47,
    SettledOutcome = 48,
    SettledQuestion = 49,
    ApprovedBuilders = 50,
    GossipPriorityAuctionStatus = 51,
    OutcomeTemplates = 52,
    Aqav2InterestHistory = 53,
    UserStarState = 54,
}

/// Complete ordered table of all 55 `InfoRequestKind` variants.
pub const ALL_INFO_REQUEST_KINDS: [InfoRequestKind; INFO_REQUEST_VARIANT_COUNT] = [
    InfoRequestKind::FileSnapshot,
    InfoRequestKind::WebData2,
    InfoRequestKind::WebData3,
    InfoRequestKind::Meta,
    InfoRequestKind::SpotMeta,
    InfoRequestKind::OutcomeMeta,
    InfoRequestKind::OutcomeDeployerLimits,
    InfoRequestKind::ClearinghouseState,
    InfoRequestKind::SpotClearinghouseState,
    InfoRequestKind::OpenOrders,
    InfoRequestKind::ExchangeStatus,
    InfoRequestKind::FrontendOpenOrders,
    InfoRequestKind::ActiveAssetData,
    InfoRequestKind::MaxMarketOrderNtls,
    InfoRequestKind::VaultSummaries,
    InfoRequestKind::UserVaultEquities,
    InfoRequestKind::LeadingVaults,
    InfoRequestKind::ExtraAgents,
    InfoRequestKind::SubAccounts,
    InfoRequestKind::SubAccounts2,
    InfoRequestKind::UserFees,
    InfoRequestKind::UserRateLimit,
    InfoRequestKind::SpotDeployState,
    InfoRequestKind::SpotPairDeployAuctionStatus,
    InfoRequestKind::PerpDeployAuctionStatus,
    InfoRequestKind::Votes,
    InfoRequestKind::Delegations,
    InfoRequestKind::DelegatorSummary,
    InfoRequestKind::MaxBuilderFee,
    InfoRequestKind::UserToMultiSigSigners,
    InfoRequestKind::UserRole,
    InfoRequestKind::PerpsAtOpenInterestCap,
    InfoRequestKind::PerpDexLimits,
    InfoRequestKind::ValidatorL1Votes,
    InfoRequestKind::MarginTable,
    InfoRequestKind::PerpDexs,
    InfoRequestKind::AllPerpMetas,
    InfoRequestKind::UserDexAbstraction,
    InfoRequestKind::PerpDexStatus,
    InfoRequestKind::BorrowLendUserState,
    InfoRequestKind::BorrowLendReserveState,
    InfoRequestKind::AllBorrowLendReserveStates,
    InfoRequestKind::UserAbstraction,
    InfoRequestKind::PerpAnnotation,
    InfoRequestKind::PerpCategories,
    InfoRequestKind::PerpConciseAnnotations,
    InfoRequestKind::TokenAnnotation,
    InfoRequestKind::TokenConciseAnnotations,
    InfoRequestKind::SettledOutcome,
    InfoRequestKind::SettledQuestion,
    InfoRequestKind::ApprovedBuilders,
    InfoRequestKind::GossipPriorityAuctionStatus,
    InfoRequestKind::OutcomeTemplates,
    InfoRequestKind::Aqav2InterestHistory,
    InfoRequestKind::UserStarState,
];

impl InfoRequestKind {
    /// Exact JSON `"type"` string serialized and matched by node #115.
    #[must_use]
    pub const fn as_wire_name(self) -> &'static str {
        match self {
            Self::FileSnapshot => "fileSnapshot",
            Self::WebData2 => "webData2",
            Self::WebData3 => "webData3",
            Self::Meta => "meta",
            Self::SpotMeta => "spotMeta",
            Self::OutcomeMeta => "outcomeMeta",
            Self::OutcomeDeployerLimits => "outcomeDeployerLimits",
            Self::ClearinghouseState => "clearinghouseState",
            Self::SpotClearinghouseState => "spotClearinghouseState",
            Self::OpenOrders => "openOrders",
            Self::ExchangeStatus => "exchangeStatus",
            Self::FrontendOpenOrders => "frontendOpenOrders",
            Self::ActiveAssetData => "activeAssetData",
            Self::MaxMarketOrderNtls => "maxMarketOrderNtls",
            Self::VaultSummaries => "vaultSummaries",
            Self::UserVaultEquities => "userVaultEquities",
            Self::LeadingVaults => "leadingVaults",
            Self::ExtraAgents => "extraAgents",
            Self::SubAccounts => "subAccounts",
            Self::SubAccounts2 => "subAccounts2",
            Self::UserFees => "userFees",
            Self::UserRateLimit => "userRateLimit",
            Self::SpotDeployState => "spotDeployState",
            Self::SpotPairDeployAuctionStatus => "spotPairDeployAuctionStatus",
            Self::PerpDeployAuctionStatus => "perpDeployAuctionStatus",
            Self::Votes => "votes",
            Self::Delegations => "delegations",
            Self::DelegatorSummary => "delegatorSummary",
            Self::MaxBuilderFee => "maxBuilderFee",
            Self::UserToMultiSigSigners => "userToMultiSigSigners",
            Self::UserRole => "userRole",
            Self::PerpsAtOpenInterestCap => "perpsAtOpenInterestCap",
            Self::PerpDexLimits => "perpDexLimits",
            Self::ValidatorL1Votes => "validatorL1Votes",
            Self::MarginTable => "marginTable",
            Self::PerpDexs => "perpDexs",
            Self::AllPerpMetas => "allPerpMetas",
            Self::UserDexAbstraction => "userDexAbstraction",
            Self::PerpDexStatus => "perpDexStatus",
            Self::BorrowLendUserState => "borrowLendUserState",
            Self::BorrowLendReserveState => "borrowLendReserveState",
            Self::AllBorrowLendReserveStates => "allBorrowLendReserveStates",
            Self::UserAbstraction => "userAbstraction",
            Self::PerpAnnotation => "perpAnnotation",
            Self::PerpCategories => "perpCategories",
            Self::PerpConciseAnnotations => "perpConciseAnnotations",
            Self::TokenAnnotation => "tokenAnnotation",
            Self::TokenConciseAnnotations => "tokenConciseAnnotations",
            Self::SettledOutcome => "settledOutcome",
            Self::SettledQuestion => "settledQuestion",
            Self::ApprovedBuilders => "approvedBuilders",
            Self::GossipPriorityAuctionStatus => "gossipPriorityAuctionStatus",
            Self::OutcomeTemplates => "outcomeTemplates",
            Self::Aqav2InterestHistory => "aqav2InterestHistory",
            Self::UserStarState => "userStarState",
        }
    }

    /// Exact discriminant index `0..=54` in `.data.rel.ro` `0x643a9e0` and jump table `0x5f45d0`.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    /// Look up by exact JSON `"type"` wire name.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        ALL_INFO_REQUEST_KINDS
            .into_iter()
            .find(|kind| kind.as_wire_name() == name)
    }

    /// Exact payload field names emitted after `"type"` by `0x273bf30` in node #115.
    #[must_use]
    pub const fn payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::FileSnapshot => &["request", "outPath", "includeHeightInOutput"],
            Self::WebData2
            | Self::WebData3
            | Self::UserVaultEquities
            | Self::LeadingVaults
            | Self::ExtraAgents
            | Self::SubAccounts2
            | Self::UserFees
            | Self::UserRateLimit
            | Self::SpotDeployState
            | Self::Votes
            | Self::Delegations
            | Self::DelegatorSummary
            | Self::UserToMultiSigSigners
            | Self::UserRole
            | Self::UserDexAbstraction
            | Self::BorrowLendUserState
            | Self::UserAbstraction
            | Self::ApprovedBuilders
            | Self::UserStarState => &["user"],
            Self::Meta
            | Self::PerpsAtOpenInterestCap
            | Self::PerpDexLimits
            | Self::PerpDexStatus => &["dex"],
            Self::SpotMeta => &["includeDebugDetails"],
            Self::OutcomeMeta
            | Self::ExchangeStatus
            | Self::MaxMarketOrderNtls
            | Self::SpotPairDeployAuctionStatus
            | Self::PerpDeployAuctionStatus
            | Self::ValidatorL1Votes
            | Self::PerpDexs
            | Self::AllPerpMetas
            | Self::AllBorrowLendReserveStates
            | Self::PerpCategories
            | Self::PerpConciseAnnotations
            | Self::TokenConciseAnnotations
            | Self::GossipPriorityAuctionStatus
            | Self::OutcomeTemplates => &[],
            Self::OutcomeDeployerLimits => &["venue"],
            Self::ClearinghouseState
            | Self::OpenOrders
            | Self::FrontendOpenOrders
            | Self::SubAccounts => &["user", "dex"],
            Self::SpotClearinghouseState => &["user", "ignorePortfolioMargin"],
            Self::ActiveAssetData => &["user", "coin"],
            Self::VaultSummaries => &["leader"],
            Self::MaxBuilderFee => &["user", "builder"],
            Self::MarginTable => &["dex", "id"],
            Self::BorrowLendReserveState
            | Self::TokenAnnotation
            | Self::Aqav2InterestHistory => &["token"],
            Self::PerpAnnotation => &["coin"],
            Self::SettledOutcome => &["outcome", "only_use_db"],
            Self::SettledQuestion => &["question", "only_use_db"],
        }
    }

    /// Exact serde `serialize_map` entry count passed in `edx` by `0x273bf30` (`1 + payload_fields().len()`).
    #[must_use]
    pub const fn serialized_map_entries(self) -> usize {
        1 + self.payload_fields().len()
    }

    /// True if this variant requires localhost access (`fileSnapshot`).
    #[must_use]
    pub const fn requires_localhost(self) -> bool {
        matches!(self, Self::FileSnapshot)
    }
}

/// 2-variant `FileSnapshotRequest` enum observed at `.data.rel.ro` `0x643ad50..0x643ad70`
/// (matched by `0x2744c00..0x2744d62`, `variant index 0 <= i < 2`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FileSnapshotKind {
    ReferrerStates = 0,
    L4Snapshots = 1,
}

impl FileSnapshotKind {
    #[must_use]
    pub const fn as_wire_name(self) -> &'static str {
        match self {
            Self::ReferrerStates => "referrerStates",
            Self::L4Snapshots => "l4Snapshots",
        }
    }

    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "referrerStates" => Some(Self::ReferrerStates),
            "l4Snapshots" => Some(Self::L4Snapshots),
            _ => None,
        }
    }

    /// Payload fields observed immediately after `l4Snapshots` at `.rodata` `0x5f65cb`.
    #[must_use]
    pub const fn payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::ReferrerStates => &[],
            Self::L4Snapshots => &["includeUsers", "includeTriggerOrders"],
        }
    }
}

/// Errors produced when inspecting the `"type"` discriminator of a raw JSON `/info` body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestParseError {
    /// Malformed JSON syntax at `(line, column)` computed by `node115-json-error-position`.
    Syntax {
        scanner_code: Option<u64>,
        line: u64,
        column: u64,
    },
    /// Top-level JSON value is not a JSON object (`{ ... }`).
    NotObject { line: u64, column: u64 },
    /// Object has no top-level `"type"` string field.
    MissingTypeField,
    /// `"type"` value was not a valid UTF-8 string.
    InvalidUtf8Type { line: u64, column: u64 },
    /// `"type"` string does not match any of the 55 node #115 `InfoRequest` variants.
    UnknownVariant(String),
}

fn syntax_err(input: &[u8], cursor: usize, scanner_code: Option<u64>) -> RequestParseError {
    let clamped = cursor.min(input.len());
    let (line, column) = json_error_position(input, clamped).unwrap_or((1, 0));
    RequestParseError::Syntax {
        scanner_code,
        line,
        column,
    }
}

fn skip_ws(input: &[u8], cursor: &mut usize) {
    while let Some(&b) = input.get(*cursor) {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            *cursor += 1;
        } else {
            break;
        }
    }
}

fn skip_json_value(input: &[u8], cursor: &mut usize) -> Result<(), RequestParseError> {
    skip_ws(input, cursor);
    let Some(&b) = input.get(*cursor) else {
        return Err(syntax_err(input, *cursor, Some(4)));
    };
    match b {
        b'"' => {
            *cursor += 1;
            let mut scratch = Vec::new();
            scan_json_string(input, cursor, &mut scratch)
                .map_err(|e| syntax_err(input, *cursor, Some(e.code)))?;
            Ok(())
        }
        b'{' => {
            *cursor += 1;
            skip_ws(input, cursor);
            if input.get(*cursor) == Some(&b'}') {
                *cursor += 1;
                return Ok(());
            }
            loop {
                skip_ws(input, cursor);
                if input.get(*cursor) != Some(&b'"') {
                    return Err(syntax_err(input, *cursor, None));
                }
                *cursor += 1;
                let mut scratch = Vec::new();
                scan_json_string(input, cursor, &mut scratch)
                    .map_err(|e| syntax_err(input, *cursor, Some(e.code)))?;
                skip_ws(input, cursor);
                if input.get(*cursor) != Some(&b':') {
                    return Err(syntax_err(input, *cursor, None));
                }
                *cursor += 1;
                skip_json_value(input, cursor)?;
                skip_ws(input, cursor);
                match input.get(*cursor) {
                    Some(b',') => *cursor += 1,
                    Some(b'}') => {
                        *cursor += 1;
                        return Ok(());
                    }
                    _ => return Err(syntax_err(input, *cursor, None)),
                }
            }
        }
        b'[' => {
            *cursor += 1;
            skip_ws(input, cursor);
            if input.get(*cursor) == Some(&b']') {
                *cursor += 1;
                return Ok(());
            }
            loop {
                skip_json_value(input, cursor)?;
                skip_ws(input, cursor);
                match input.get(*cursor) {
                    Some(b',') => *cursor += 1,
                    Some(b']') => {
                        *cursor += 1;
                        return Ok(());
                    }
                    _ => return Err(syntax_err(input, *cursor, None)),
                }
            }
        }
        _ => {
            let start = *cursor;
            while let Some(&c) = input.get(*cursor) {
                if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                *cursor += 1;
            }
            if *cursor == start {
                return Err(syntax_err(input, *cursor, None));
            }
            Ok(())
        }
    }
}

/// Parse the top-level `"type"` discriminator of a `/info` JSON request body using
/// node #115's strict string scanner (`node115-json-string-scanner`) and line/column
/// locator (`node115-json-error-position`).
pub fn parse_info_request_kind(json_body: &[u8]) -> Result<InfoRequestKind, RequestParseError> {
    let mut cursor = 0usize;
    skip_ws(json_body, &mut cursor);
    if json_body.get(cursor) != Some(&b'{') {
        let (line, column) = json_error_position(json_body, cursor.min(json_body.len())).unwrap_or((1, 0));
        return Err(RequestParseError::NotObject { line, column });
    }
    cursor += 1;
    skip_ws(json_body, &mut cursor);
    if json_body.get(cursor) == Some(&b'}') {
        return Err(RequestParseError::MissingTypeField);
    }

    let mut scratch = Vec::new();
    let mut found_type: Option<String> = None;
    loop {
        skip_ws(json_body, &mut cursor);
        if json_body.get(cursor) != Some(&b'"') {
            return Err(syntax_err(json_body, cursor, None));
        }
        cursor += 1;
        scratch.clear();
        let key_bytes = match scan_json_string(json_body, &mut cursor, &mut scratch)
            .map_err(|e| syntax_err(json_body, cursor, Some(e.code)))?
        {
            ScanOutput::Borrowed(b) | ScanOutput::Scratch(b) => b.to_vec(),
        };
        skip_ws(json_body, &mut cursor);
        if json_body.get(cursor) != Some(&b':') {
            return Err(syntax_err(json_body, cursor, None));
        }
        cursor += 1;
        skip_ws(json_body, &mut cursor);

        if key_bytes == INFO_REQUEST_TAG_KEY.as_bytes() {
            if json_body.get(cursor) != Some(&b'"') {
                return Err(syntax_err(json_body, cursor, None));
            }
            let value_pos = cursor;
            cursor += 1;
            scratch.clear();
            let val_bytes = match scan_json_string(json_body, &mut cursor, &mut scratch)
                .map_err(|e| syntax_err(json_body, cursor, Some(e.code)))?
            {
                ScanOutput::Borrowed(b) | ScanOutput::Scratch(b) => b.to_vec(),
            };
            let val_str = String::from_utf8(val_bytes).map_err(|_| {
                let (line, column) = json_error_position(json_body, value_pos).unwrap_or((1, 0));
                RequestParseError::InvalidUtf8Type { line, column }
            })?;
            found_type = Some(val_str);
        } else {
            skip_json_value(json_body, &mut cursor)?;
        }

        skip_ws(json_body, &mut cursor);
        match json_body.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b'}') => {
                cursor += 1;
                break;
            }
            _ => return Err(syntax_err(json_body, cursor, None)),
        }
    }

    skip_ws(json_body, &mut cursor);
    if cursor != json_body.len() {
        return Err(syntax_err(json_body, cursor, None));
    }

    let wire = found_type.ok_or(RequestParseError::MissingTypeField)?;
    InfoRequestKind::from_wire_name(&wire).ok_or(RequestParseError::UnknownVariant(wire))
}
