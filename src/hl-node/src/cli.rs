//! Node #115 CLI command & common-option parser grounded in:
//! - `RE-012-node115-cli-command-factory` (`0x564e1a0..0x56544a9`, 14 subcommands + version `"0.1.0"`)
//! - `RE-012-node115-cli-common-settings` (`0x5656bf0`, 14 common options + `--serve-eth-rpc` alias)
//! - `node115-cli-validators` (`0x56544b0`, `0x56546c0`, `0x56547d0`)
//! - `node115-startup-output` (`OutputSettings`, `ReplicaStyle`)

use std::collections::{BTreeMap, BTreeSet};

use global_constants::ChainName;
use node_runtime::aux::AuxStreamConfig;
use node115_cli_validators::{accepts_lowercase_bool, accepts_u64_decimal, validate_node_ip};
use node115_startup_output::{OutputSettings, ReplicaStyle, StyleError};

pub const VERSION: &str = "0.1.0";

/// All 14 subcommands declared by the node #115 CLI factory (`0x564e1a0..0x56544a9`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Subcommand {
    RunNonValidator,
    RunValidator,
    PrintAddress,
    ApproveNonExpiringAgent,
    TranslateAbciState,
    SendSignedAction,
    Delegate,
    StakingDeposit,
    StakingWithdrawal,
    SendSlackAlert,
    CheckReachability,
    ComputeReferrerStates,
    ComputeL4Snapshots,
    ChangeValidatorProfile,
}

impl Subcommand {
    pub const ALL: [Subcommand; 14] = [
        Subcommand::RunNonValidator,
        Subcommand::RunValidator,
        Subcommand::PrintAddress,
        Subcommand::ApproveNonExpiringAgent,
        Subcommand::TranslateAbciState,
        Subcommand::SendSignedAction,
        Subcommand::Delegate,
        Subcommand::StakingDeposit,
        Subcommand::StakingWithdrawal,
        Subcommand::SendSlackAlert,
        Subcommand::CheckReachability,
        Subcommand::ComputeReferrerStates,
        Subcommand::ComputeL4Snapshots,
        Subcommand::ChangeValidatorProfile,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Subcommand::RunNonValidator => "run-non-validator",
            Subcommand::RunValidator => "run-validator",
            Subcommand::PrintAddress => "print-address",
            Subcommand::ApproveNonExpiringAgent => "approve-non-expiring-agent",
            Subcommand::TranslateAbciState => "translate-abci-state",
            Subcommand::SendSignedAction => "send-signed-action",
            Subcommand::Delegate => "delegate",
            Subcommand::StakingDeposit => "staking-deposit",
            Subcommand::StakingWithdrawal => "staking-withdrawal",
            Subcommand::SendSlackAlert => "send-slack-alert",
            Subcommand::CheckReachability => "check-reachability",
            Subcommand::ComputeReferrerStates => "compute-referrer-states",
            Subcommand::ComputeL4Snapshots => "compute-l4-snapshots",
            Subcommand::ChangeValidatorProfile => "change-validator-profile",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "run-non-validator" => Some(Subcommand::RunNonValidator),
            "run-validator" => Some(Subcommand::RunValidator),
            "print-address" => Some(Subcommand::PrintAddress),
            "approve-non-expiring-agent" => Some(Subcommand::ApproveNonExpiringAgent),
            "translate-abci-state" => Some(Subcommand::TranslateAbciState),
            "send-signed-action" => Some(Subcommand::SendSignedAction),
            "delegate" => Some(Subcommand::Delegate),
            "staking-deposit" => Some(Subcommand::StakingDeposit),
            "staking-withdrawal" => Some(Subcommand::StakingWithdrawal),
            "send-slack-alert" => Some(Subcommand::SendSlackAlert),
            "check-reachability" => Some(Subcommand::CheckReachability),
            "compute-referrer-states" => Some(Subcommand::ComputeReferrerStates),
            "compute-l4-snapshots" => Some(Subcommand::ComputeL4Snapshots),
            "change-validator-profile" => Some(Subcommand::ChangeValidatorProfile),
            _ => None,
        }
    }

    pub const fn uses_common_run_options(self) -> bool {
        matches!(self, Subcommand::RunNonValidator | Subcommand::RunValidator)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliAction {
    Help,
    Version,
    Command(ParsedCommand),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCommand {
    pub chain: ChainName,
    pub subcommand: Subcommand,
    pub flags: BTreeSet<String>,
    pub values: BTreeMap<String, String>,
    pub output_settings: Option<OutputSettings>,
    pub aux_config: Option<AuxStreamConfig>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    MissingSubcommand,
    UnknownSubcommand(String),
    UnknownOption(String),
    MissingOptionValue(String),
    MissingRequiredOption(&'static str),
    InvalidChain(String),
    InvalidU64 { option: &'static str, value: String },
    InvalidBool { option: &'static str, value: String },
    InvalidNodeIp(String),
    InvalidReplicaStyle(String),
    AuxConfigConflict(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::MissingSubcommand => write!(f, "missing subcommand (try --help)"),
            CliError::UnknownSubcommand(s) => write!(f, "unknown subcommand: {s}"),
            CliError::UnknownOption(o) => write!(f, "unknown option: {o}"),
            CliError::MissingOptionValue(o) => write!(f, "missing value for option: --{o}"),
            CliError::MissingRequiredOption(o) => write!(f, "missing required option: --{o}"),
            CliError::InvalidChain(c) => {
                write!(f, "invalid --chain {c:?}; expected Local, Sandbox, Testnet, or Mainnet")
            }
            CliError::InvalidU64 { option, value } => {
                write!(f, "invalid u64 value {value:?} for --{option}")
            }
            CliError::InvalidBool { option, value } => {
                write!(f, "invalid boolean {value:?} for --{option}; expected true or false")
            }
            CliError::InvalidNodeIp(ip) => write!(f, "NodeIpParseError: {ip:?}"),
            CliError::InvalidReplicaStyle(s) => {
                write!(f, "Matching variant not found for --replica-cmds-style: {s:?}")
            }
            CliError::AuxConfigConflict(msg) => write!(f, "aux stream config conflict: {msg}"),
        }
    }
}

const COMMON_FLAGS: &[&str] = &[
    "write-trades",
    "write-fills",
    "write-raw-book-diffs",
    "write-order-statuses",
    "write-misc-events",
    "write-hip3-oracle-updates",
    "write-system-and-core-writer-actions",
    "disable-output-file-buffering",
    "batch-by-block",
    "stream-with-block-info",
    "serve-evm-rpc",
    "serve-info",
    "dry-run",
];

const COMMON_VALUES: &[&str] = &[
    "write-user-clearinghouse-states",
    "replica-cmds-style",
    "data-dir",
    "http-bind",
];

fn parse_chain(s: &str) -> Option<ChainName> {
    match s {
        "Local" => Some(ChainName::Local),
        "Sandbox" => Some(ChainName::Sandbox),
        "Testnet" => Some(ChainName::Testnet),
        "Mainnet" => Some(ChainName::Mainnet),
        _ => None,
    }
}

fn is_flag_for(sub: Subcommand, opt: &str) -> bool {
    if sub.uses_common_run_options() && COMMON_FLAGS.contains(&opt) {
        return true;
    }
    match sub {
        Subcommand::Delegate => opt == "undelegate",
        Subcommand::ComputeL4Snapshots => {
            matches!(opt, "include-users" | "include-trigger-orders")
        }
        Subcommand::ChangeValidatorProfile => opt == "unjailed",
        _ => false,
    }
}

fn is_value_for(sub: Subcommand, opt: &str) -> bool {
    if sub.uses_common_run_options() && COMMON_VALUES.contains(&opt) {
        return true;
    }
    match sub {
        Subcommand::TranslateAbciState => matches!(opt, "in-fln" | "out-fln"),
        Subcommand::SendSignedAction => opt == "action",
        Subcommand::Delegate => matches!(opt, "validator" | "wei"),
        Subcommand::StakingDeposit | Subcommand::StakingWithdrawal => opt == "wei",
        Subcommand::SendSlackAlert => opt == "msg",
        Subcommand::CheckReachability => opt == "abci-state-fln",
        Subcommand::ComputeReferrerStates | Subcommand::ComputeL4Snapshots => {
            matches!(opt, "abci-state-fln" | "out-fln")
        }
        Subcommand::ChangeValidatorProfile => matches!(
            opt,
            "abci-state-fln"
                | "node-ip"
                | "name"
                | "description"
                | "disable-delegations"
                | "commission-bps"
                | "signer"
        ),
        _ => false,
    }
}

fn required_options_for(sub: Subcommand) -> &'static [&'static str] {
    match sub {
        Subcommand::TranslateAbciState => &["in-fln", "out-fln"],
        Subcommand::SendSignedAction => &["action"],
        Subcommand::Delegate => &["validator", "wei"],
        Subcommand::StakingDeposit | Subcommand::StakingWithdrawal => &["wei"],
        Subcommand::SendSlackAlert => &["msg"],
        Subcommand::CheckReachability => &["abci-state-fln"],
        Subcommand::ComputeReferrerStates | Subcommand::ComputeL4Snapshots => {
            &["abci-state-fln", "out-fln"]
        }
        Subcommand::ChangeValidatorProfile => &["abci-state-fln"],
        _ => &[],
    }
}

pub fn parse_args<I, S>(args: I) -> Result<CliAction, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let items: Vec<String> = args.into_iter().map(Into::into).collect();
    if items.is_empty() {
        return Err(CliError::MissingSubcommand);
    }

    let mut idx = 0;
    let mut chain = None;
    let mut subcommand: Option<Subcommand> = None;
    let mut flags = BTreeSet::new();
    let mut values = BTreeMap::new();

    while idx < items.len() {
        let tok = &items[idx];
        if tok == "--help" || tok == "-h" {
            return Ok(CliAction::Help);
        }
        if tok == "--version" || tok == "-V" {
            return Ok(CliAction::Version);
        }
        if tok == "--chain" {
            idx += 1;
            let raw = items
                .get(idx)
                .ok_or_else(|| CliError::MissingOptionValue("chain".to_string()))?;
            chain = Some(parse_chain(raw).ok_or_else(|| CliError::InvalidChain(raw.clone()))?);
            idx += 1;
            continue;
        }
        if let Some(raw) = tok.strip_prefix("--chain=") {
            chain = Some(parse_chain(raw).ok_or_else(|| CliError::InvalidChain(raw.to_string()))?);
            idx += 1;
            continue;
        }

        if subcommand.is_none() {
            if tok.starts_with('-') {
                return Err(CliError::UnknownOption(tok.clone()));
            }
            let sub = Subcommand::parse(tok)
                .ok_or_else(|| CliError::UnknownSubcommand(tok.clone()))?;
            subcommand = Some(sub);
            idx += 1;
            continue;
        }

        let sub = subcommand.unwrap();
        let Some(rest) = tok.strip_prefix("--") else {
            return Err(CliError::UnknownOption(tok.clone()));
        };
        let (raw_name, inline_val) = match rest.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (rest, None),
        };
        // Hidden alias observed at 0x5658d67 / 0x5658dc6 (`serve-eth-rpc` -> `serve-evm-rpc`).
        let name = if raw_name == "serve-eth-rpc" {
            "serve-evm-rpc"
        } else {
            raw_name
        };

        if is_flag_for(sub, name) && inline_val.is_none() {
            flags.insert(name.to_string());
            idx += 1;
        } else if is_value_for(sub, name) {
            let val = match inline_val {
                Some(v) => v,
                None => {
                    idx += 1;
                    items
                        .get(idx)
                        .ok_or_else(|| CliError::MissingOptionValue(name.to_string()))?
                        .clone()
                }
            };
            values.insert(name.to_string(), val);
            idx += 1;
        } else {
            return Err(CliError::UnknownOption(tok.clone()));
        }
    }

    let sub = subcommand.ok_or(CliError::MissingSubcommand)?;
    let chain = chain.ok_or(CliError::MissingRequiredOption("chain"))?;

    for req in required_options_for(sub) {
        if !values.contains_key(*req) {
            return Err(CliError::MissingRequiredOption(req));
        }
    }

    if let Some(wei) = values.get("wei")
        && !accepts_u64_decimal(wei.as_bytes())
    {
        return Err(CliError::InvalidU64 {
            option: "wei",
            value: wei.clone(),
        });
    }
    if let Some(bps) = values.get("commission-bps")
        && !accepts_u64_decimal(bps.as_bytes())
    {
        return Err(CliError::InvalidU64 {
            option: "commission-bps",
            value: bps.clone(),
        });
    }
    if let Some(flag) = values.get("disable-delegations")
        && !accepts_lowercase_bool(flag.as_bytes())
    {
        return Err(CliError::InvalidBool {
            option: "disable-delegations",
            value: flag.clone(),
        });
    }
    if let Some(ip) = values.get("node-ip")
        && validate_node_ip(ip.as_bytes()).is_err()
    {
        return Err(CliError::InvalidNodeIp(ip.clone()));
    }

    let output_settings = if sub.uses_common_run_options() {
        let style_default = values
            .get("replica-cmds-style")
            .map(String::as_str)
            .unwrap_or("actions");
        match OutputSettings::read(
            |name| flags.contains(name),
            |name| {
                if name == "replica-cmds-style" {
                    Some(style_default.as_bytes())
                } else {
                    values.get(name).map(String::as_bytes)
                }
            },
        ) {
            Ok(settings) => Some(settings),
            Err(StyleError::Missing | StyleError::Unrecognized) => {
                return Err(CliError::InvalidReplicaStyle(style_default.to_string()));
            }
        }
    } else {
        None
    };

    let aux_config = if sub.uses_common_run_options() {
        let mut enabled_streams = Vec::new();
        for (flag_name, stream_name) in [
            ("write-trades", "node_trades"),
            ("write-fills", "node_fills"),
            ("write-raw-book-diffs", "node_raw_book_diffs"),
            ("write-order-statuses", "node_order_statuses"),
            ("write-misc-events", "misc_events"),
            ("write-hip3-oracle-updates", "hip3_oracle_updates"),
            (
                "write-system-and-core-writer-actions",
                "system_and_core_writer_actions",
            ),
        ] {
            if flags.contains(flag_name) {
                enabled_streams.push(stream_name);
            }
        }
        if values.contains_key("write-user-clearinghouse-states") {
            enabled_streams.push("dex_user_clearinghouse_states");
        }
        let cfg = AuxStreamConfig {
            batch_by_block: flags.contains("batch-by-block"),
            stream_with_block_info: flags.contains("stream-with-block-info"),
            enabled_streams,
        };
        cfg.validate()
            .map_err(|e| CliError::AuxConfigConflict(e.to_string()))?;
        Some(cfg)
    } else {
        None
    };

    Ok(CliAction::Command(ParsedCommand {
        chain,
        subcommand: sub,
        flags,
        values,
        output_settings,
        aux_config,
    }))
}

pub fn replica_style_label(style: &ReplicaStyle) -> &'static str {
    match style {
        ReplicaStyle::Actions => "actions",
        ReplicaStyle::ActionsAndResponses => "actions-and-responses",
        ReplicaStyle::RecentActions => "recent-actions",
    }
}

pub fn help_text() -> String {
    let mut out = format!(
        "hl-node {VERSION} (independent node #115 workspace reconstruction)\n\
         \n\
         USAGE:\n    hl-node --chain <Local|Sandbox|Testnet|Mainnet> <SUBCOMMAND> [OPTIONS]\n\
         \n\
         SUBCOMMANDS:\n"
    );
    for sub in Subcommand::ALL {
        out.push_str(&format!("    {}\n", sub.as_str()));
    }
    out.push_str(
        "\nCOMMON RUN OPTIONS (run-non-validator / run-validator):\n\
         \x20   --write-trades, --write-fills, --write-raw-book-diffs, --write-order-statuses,\n\
         \x20   --write-misc-events, --write-hip3-oracle-updates, --write-user-clearinghouse-states <VAL>,\n\
         \x20   --write-system-and-core-writer-actions, --disable-output-file-buffering,\n\
         \x20   --batch-by-block, --stream-with-block-info, --serve-evm-rpc (alias --serve-eth-rpc),\n\
         \x20   --serve-info, --replica-cmds-style <actions|recent-actions|actions-and-responses>, --dry-run\n",
    );
    out
}
