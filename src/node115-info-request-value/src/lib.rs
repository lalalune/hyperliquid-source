//! Node115 InfoRequest logical value construction.
//! Independently authored API; native layout, allocation and wire ABI are not claimed.
pub type Address = [u8; 20];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    String(String),
    /// Unique fields in the observed construction order, not a native map layout.
    Object(Vec<(&'static str, RequestValue)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileSnapshotRequest<'a> {
    ReferrerStates,
    L4Snapshots {
        coin: Option<&'a str>,
        include_users: bool,
        include_trigger_orders: bool,
        include_l4_details: bool,
    },
}

fn text(value: &str) -> RequestValue {
    RequestValue::String(value.to_owned())
}

fn unsigned(value: u64) -> RequestValue {
    RequestValue::Unsigned(value)
}

fn address(value: &Address) -> RequestValue {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    RequestValue::String(out)
}

fn optional_address(value: &Option<Address>) -> RequestValue {
    value.as_ref().map_or(RequestValue::Null, address)
}

fn record<const N: usize>(
    kind: &'static str,
    fields: [(&'static str, RequestValue); N],
) -> RequestValue {
    let mut members = Vec::with_capacity(N + 1);
    members.push(("type", text(kind)));
    members.extend(fields);
    RequestValue::Object(members)
}

fn snapshot_value(value: &FileSnapshotRequest<'_>) -> RequestValue {
    match value {
        FileSnapshotRequest::ReferrerStates => record("referrerStates", []),
        FileSnapshotRequest::L4Snapshots {
            coin,
            include_users,
            include_trigger_orders,
            include_l4_details,
        } => {
            let mut fields = Vec::with_capacity(5);
            fields.push(("type", text("l4Snapshots")));
            fields.push(("includeUsers", RequestValue::Bool(*include_users)));
            fields.push((
                "includeTriggerOrders",
                RequestValue::Bool(*include_trigger_orders),
            ));
            if let Some(coin) = coin {
                fields.push(("coin", text(coin)));
            }
            if *include_l4_details {
                fields.push(("includeL4Details", RequestValue::Bool(true)));
            }
            RequestValue::Object(fields)
        }
    }
}

/// Own logical request types. Their memory layout is not the captured enum ABI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InfoRequest<'a> {
    FileSnapshot {
        request: FileSnapshotRequest<'a>,
        out_path: &'a str,
        include_height_in_output: bool,
    },
    WebData2 {
        user: Option<Address>,
    },
    WebData3 {
        user: Address,
    },
    Meta {
        dex: &'a str,
    },
    SpotMeta {
        include_debug_details: bool,
    },
    OutcomeMeta,
    OutcomeDeployerLimits {
        venue: &'a str,
    },
    ClearinghouseState {
        user: Address,
        dex: &'a str,
    },
    SpotClearinghouseState {
        user: Address,
        ignore_portfolio_margin: bool,
    },
    OpenOrders {
        user: Address,
        dex: &'a str,
    },
    ExchangeStatus,
    FrontendOpenOrders {
        user: Address,
        dex: &'a str,
    },
    ActiveAssetData {
        user: Address,
        coin: &'a str,
    },
    MaxMarketOrderNtls,
    VaultSummaries {
        leader: Option<Address>,
    },
    UserVaultEquities {
        user: Address,
    },
    LeadingVaults {
        user: Address,
    },
    ExtraAgents {
        user: Address,
    },
    SubAccounts {
        user: Address,
        dex: &'a str,
    },
    SubAccounts2 {
        user: Address,
    },
    UserFees {
        user: Address,
    },
    UserRateLimit {
        user: Address,
    },
    SpotDeployState {
        user: Address,
    },
    SpotPairDeployAuctionStatus,
    PerpDeployAuctionStatus,
    Votes {
        user: Address,
    },
    Delegations {
        user: Address,
    },
    DelegatorSummary {
        user: Address,
    },
    MaxBuilderFee {
        user: Address,
        builder: Address,
    },
    UserToMultiSigSigners {
        user: Address,
    },
    UserRole {
        user: Address,
    },
    PerpsAtOpenInterestCap {
        dex: &'a str,
    },
    PerpDexLimits {
        dex: &'a str,
    },
    ValidatorL1Votes,
    MarginTable {
        dex: &'a str,
        id: u32,
    },
    PerpDexs,
    AllPerpMetas,
    UserDexAbstraction {
        user: Address,
    },
    PerpDexStatus {
        dex: &'a str,
    },
    BorrowLendUserState {
        user: Address,
    },
    BorrowLendReserveState {
        token: u64,
    },
    AllBorrowLendReserveStates,
    UserAbstraction {
        user: Address,
    },
    PerpAnnotation {
        coin: &'a str,
    },
    PerpCategories,
    PerpConciseAnnotations,
    TokenAnnotation {
        token: u64,
    },
    TokenConciseAnnotations,
    SettledOutcome {
        outcome: u64,
        only_use_db: bool,
    },
    SettledQuestion {
        question: u64,
        only_use_db: bool,
    },
    ApprovedBuilders {
        user: Address,
    },
    GossipPriorityAuctionStatus,
    OutcomeTemplates,
    Aqav2InterestHistory {
        token: u64,
    },
    UserStarState {
        user: Address,
    },
}

/// Construct the complete 55-kind logical value on valid typed inputs.
/// Fresh object state makes ordinary serializer-state errors unreachable.
/// Native allocation, panic/unwind, native type layout and later wire bytes are unclaimed.
pub fn to_value(request: &InfoRequest<'_>) -> RequestValue {
    match request {
        InfoRequest::FileSnapshot {
            request,
            out_path,
            include_height_in_output,
        } => record(
            "fileSnapshot",
            [
                ("request", snapshot_value(request)),
                ("outPath", text(out_path)),
                (
                    "includeHeightInOutput",
                    RequestValue::Bool(*include_height_in_output),
                ),
            ],
        ),
        InfoRequest::WebData2 { user } => record("webData2", [("user", optional_address(user))]),
        InfoRequest::WebData3 { user } => record("webData3", [("user", address(user))]),
        InfoRequest::Meta { dex } => record("meta", [("dex", text(dex))]),
        InfoRequest::SpotMeta {
            include_debug_details,
        } => record(
            "spotMeta",
            [(
                "includeDebugDetails",
                RequestValue::Bool(*include_debug_details),
            )],
        ),
        InfoRequest::OutcomeMeta => record("outcomeMeta", []),
        InfoRequest::OutcomeDeployerLimits { venue } => {
            record("outcomeDeployerLimits", [("venue", text(venue))])
        }
        InfoRequest::ClearinghouseState { user, dex } => record(
            "clearinghouseState",
            [("user", address(user)), ("dex", text(dex))],
        ),
        InfoRequest::SpotClearinghouseState {
            user,
            ignore_portfolio_margin,
        } => record(
            "spotClearinghouseState",
            [
                ("user", address(user)),
                (
                    "ignorePortfolioMargin",
                    RequestValue::Bool(*ignore_portfolio_margin),
                ),
            ],
        ),
        InfoRequest::OpenOrders { user, dex } => {
            record("openOrders", [("user", address(user)), ("dex", text(dex))])
        }
        InfoRequest::ExchangeStatus => record("exchangeStatus", []),
        InfoRequest::FrontendOpenOrders { user, dex } => record(
            "frontendOpenOrders",
            [("user", address(user)), ("dex", text(dex))],
        ),
        InfoRequest::ActiveAssetData { user, coin } => record(
            "activeAssetData",
            [("user", address(user)), ("coin", text(coin))],
        ),
        InfoRequest::MaxMarketOrderNtls => record("maxMarketOrderNtls", []),
        InfoRequest::VaultSummaries { leader } => {
            record("vaultSummaries", [("leader", optional_address(leader))])
        }
        InfoRequest::UserVaultEquities { user } => {
            record("userVaultEquities", [("user", address(user))])
        }
        InfoRequest::LeadingVaults { user } => record("leadingVaults", [("user", address(user))]),
        InfoRequest::ExtraAgents { user } => record("extraAgents", [("user", address(user))]),
        InfoRequest::SubAccounts { user, dex } => {
            record("subAccounts", [("user", address(user)), ("dex", text(dex))])
        }
        InfoRequest::SubAccounts2 { user } => record("subAccounts2", [("user", address(user))]),
        InfoRequest::UserFees { user } => record("userFees", [("user", address(user))]),
        InfoRequest::UserRateLimit { user } => record("userRateLimit", [("user", address(user))]),
        InfoRequest::SpotDeployState { user } => {
            record("spotDeployState", [("user", address(user))])
        }
        InfoRequest::SpotPairDeployAuctionStatus => record("spotPairDeployAuctionStatus", []),
        InfoRequest::PerpDeployAuctionStatus => record("perpDeployAuctionStatus", []),
        InfoRequest::Votes { user } => record("votes", [("user", address(user))]),
        InfoRequest::Delegations { user } => record("delegations", [("user", address(user))]),
        InfoRequest::DelegatorSummary { user } => {
            record("delegatorSummary", [("user", address(user))])
        }
        InfoRequest::MaxBuilderFee { user, builder } => record(
            "maxBuilderFee",
            [("user", address(user)), ("builder", address(builder))],
        ),
        InfoRequest::UserToMultiSigSigners { user } => {
            record("userToMultiSigSigners", [("user", address(user))])
        }
        InfoRequest::UserRole { user } => record("userRole", [("user", address(user))]),
        InfoRequest::PerpsAtOpenInterestCap { dex } => {
            record("perpsAtOpenInterestCap", [("dex", text(dex))])
        }
        InfoRequest::PerpDexLimits { dex } => record("perpDexLimits", [("dex", text(dex))]),
        InfoRequest::ValidatorL1Votes => record("validatorL1Votes", []),
        InfoRequest::MarginTable { dex, id } => record(
            "marginTable",
            [("dex", text(dex)), ("id", unsigned(u64::from(*id)))],
        ),
        InfoRequest::PerpDexs => record("perpDexs", []),
        InfoRequest::AllPerpMetas => record("allPerpMetas", []),
        InfoRequest::UserDexAbstraction { user } => {
            record("userDexAbstraction", [("user", address(user))])
        }
        InfoRequest::PerpDexStatus { dex } => record("perpDexStatus", [("dex", text(dex))]),
        InfoRequest::BorrowLendUserState { user } => {
            record("borrowLendUserState", [("user", address(user))])
        }
        InfoRequest::BorrowLendReserveState { token } => {
            record("borrowLendReserveState", [("token", unsigned(*token))])
        }
        InfoRequest::AllBorrowLendReserveStates => record("allBorrowLendReserveStates", []),
        InfoRequest::UserAbstraction { user } => {
            record("userAbstraction", [("user", address(user))])
        }
        InfoRequest::PerpAnnotation { coin } => record("perpAnnotation", [("coin", text(coin))]),
        InfoRequest::PerpCategories => record("perpCategories", []),
        InfoRequest::PerpConciseAnnotations => record("perpConciseAnnotations", []),
        InfoRequest::TokenAnnotation { token } => {
            record("tokenAnnotation", [("token", unsigned(*token))])
        }
        InfoRequest::TokenConciseAnnotations => record("tokenConciseAnnotations", []),
        InfoRequest::SettledOutcome {
            outcome,
            only_use_db,
        } => record(
            "settledOutcome",
            [
                ("outcome", unsigned(*outcome)),
                ("only_use_db", RequestValue::Bool(*only_use_db)),
            ],
        ),
        InfoRequest::SettledQuestion {
            question,
            only_use_db,
        } => record(
            "settledQuestion",
            [
                ("question", unsigned(*question)),
                ("only_use_db", RequestValue::Bool(*only_use_db)),
            ],
        ),
        InfoRequest::ApprovedBuilders { user } => {
            record("approvedBuilders", [("user", address(user))])
        }
        InfoRequest::GossipPriorityAuctionStatus => record("gossipPriorityAuctionStatus", []),
        InfoRequest::OutcomeTemplates => record("outcomeTemplates", []),
        InfoRequest::Aqav2InterestHistory { token } => {
            record("aqav2InterestHistory", [("token", unsigned(*token))])
        }
        InfoRequest::UserStarState { user } => record("userStarState", [("user", address(user))]),
    }
}
