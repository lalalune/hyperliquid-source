//! CLI parsing and validation matching node #115 `node/src/hl_node.rs`
//! (`.rodata` `0x92ab70..0x92ade0`, `node115-cli-validators`, `node115-startup-output`).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use node115_cli_validators::{accepts_lowercase_bool, accepts_u64_decimal, validate_node_ip};
use node115_startup_output::{OutputSettings, ReplicaStyle};

use crate::error::NodeError;

/// Observed build metadata string at `.rodata 0x92a8d9` in node #115.
pub const NODE115_BUILD_STAMP: &str =
    "28076c144c66d3f34ca321ac85ca19f461ade137|2026-10-25 16:48:13 +0800|uncommitted=false";

pub const PROGRAM_NAME: &str = "hl-node";
pub const PROGRAM_VERSION: &str = "0.1.0";
pub const PROGRAM_ABOUT: &str = "Reference implementation of Hyperliquid protocol";

/// Chain identifiers observed at `.rodata 0x92ab52` (`Local`, `Sandbox`, `Testnet`, `Mainnet`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Chain {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

impl Chain {
    pub fn parse(s: &str) -> Result<Self, NodeError> {
        match s {
            "Local" => Ok(Self::Local),
            "Sandbox" => Ok(Self::Sandbox),
            "Testnet" => Ok(Self::Testnet),
            "Mainnet" => Ok(Self::Mainnet),
            other => Err(NodeError::Cli(format!("unknown chain: {other}"))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::Sandbox => "Sandbox",
            Self::Testnet => "Testnet",
            Self::Mainnet => "Mainnet",
        }
    }
}

/// Parsed top-level `hl-node` CLI command covering all 9 subcommands observed in
/// `.rodata 0x92aca7..0x92adc5`.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    RunNonValidator {
        output: OutputSettings,
    },
    TranslateAbciState {
        in_fln: String,
        out_fln: String,
    },
    SendSignedAction {
        action: String,
        wei: Option<u64>,
        undelegate: bool,
        staking_withdrawal: bool,
        msg: Option<String>,
    },
    CheckReachability {
        abci_state_fln: String,
    },
    ComputeReferrerStates,
    ComputeL4Snapshots {
        include_users: bool,
        include_trigger_orders: bool,
    },
    ChangeValidatorProfile {
        node_ip: Option<Ipv4Addr>,
        description: Option<String>,
        disable_delegations: Option<bool>,
        commission_bps: Option<u64>,
        signer: Option<String>,
    },
    ApproveNonExpiringAgent {
        max: bool,
    },
    ServeEthRpc,
}

/// Top-level parsed CLI arguments (`--chain <Chain> <subcommand> [flags...]`).
#[derive(Debug, PartialEq, Eq)]
pub struct CliArgs {
    pub chain: Chain,
    pub command: Command,
}

/// Parse an argument vector (excluding argv[0]) using node #115's exact CLI flag
/// names, validators (`node115-cli-validators`), and output settings reader
/// (`node115-startup-output`).
pub fn parse_args<S: AsRef<str>>(args: &[S]) -> Result<CliArgs, NodeError> {
    let mut chain = None;
    let mut subcmd_idx = None;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_ref();
        if tok == "--chain" {
            let val = args
                .get(i + 1)
                .ok_or_else(|| NodeError::Cli("missing value for --chain".into()))?;
            chain = Some(Chain::parse(val.as_ref())?);
            i += 2;
        } else if let Some(rest) = tok.strip_prefix("--chain=") {
            chain = Some(Chain::parse(rest)?);
            i += 1;
        } else if !tok.starts_with('-') {
            subcmd_idx = Some(i);
            break;
        } else {
            return Err(NodeError::Cli(format!("unexpected top-level flag: {tok}")));
        }
    }

    let chain = chain.ok_or_else(|| NodeError::Cli("The chain is required".into()))?;
    let idx = subcmd_idx.ok_or_else(|| NodeError::Cli("missing subcommand".into()))?;
    let subcmd = args[idx].as_ref();
    let rest: Vec<&str> = args[idx + 1..].iter().map(AsRef::as_ref).collect();
    let (flags, values) = parse_flags(&rest)?;

    let command = match subcmd {
        "run-non-validator" => {
            let output = OutputSettings::read(
                |name| flags.contains_key(name),
                |name| {
                    values
                        .get(name)
                        .map(|s| s.as_bytes())
                        .or_else(|| (name == "replica-cmds-style").then_some(b"actions".as_slice()))
                },
            )
            .map_err(|e| NodeError::Cli(format!("invalid output settings: {e:?}")))?;
            Command::RunNonValidator { output }
        }
        "translate-abci-state" => Command::TranslateAbciState {
            in_fln: require_val(&values, "in-fln")?,
            out_fln: require_val(&values, "out-fln")?,
        },
        "send-signed-action" => {
            let wei = match values.get("wei") {
                Some(s) => Some(parse_u64_validated(s, "wei")?),
                None => None,
            };
            Command::SendSignedAction {
                action: require_val(&values, "action")?,
                wei,
                undelegate: flags.contains_key("undelegate"),
                staking_withdrawal: flags.contains_key("staking-withdrawal"),
                msg: values.get("msg").cloned(),
            }
        }
        "check-reachability" => Command::CheckReachability {
            abci_state_fln: require_val(&values, "abci-state-fln")?,
        },
        "compute-referrer-states" => Command::ComputeReferrerStates,
        "compute-l4-snapshots" => Command::ComputeL4Snapshots {
            include_users: flags.contains_key("include-users"),
            include_trigger_orders: flags.contains_key("include-trigger-orders"),
        },
        "change-validator-profile" => {
            let node_ip = match values.get("node-ip") {
                Some(s) => {
                    validate_node_ip(s.as_bytes()).map_err(|e| NodeError::Cli(e.to_string()))?;
                    Some(
                        s.parse::<Ipv4Addr>()
                            .map_err(|_| NodeError::Cli("NodeIpParseError".into()))?,
                    )
                }
                None => None,
            };
            let disable_delegations = match values.get("disable-delegations") {
                Some(s) => Some(parse_bool_validated(s, "disable-delegations")?),
                None => None,
            };
            let commission_bps = match values.get("commission-bps") {
                Some(s) => Some(parse_u64_validated(s, "commission-bps")?),
                None => None,
            };
            Command::ChangeValidatorProfile {
                node_ip,
                description: values.get("description").cloned(),
                disable_delegations,
                commission_bps,
                signer: values.get("signer").cloned(),
            }
        }
        "approve-non-expiring-agent" => Command::ApproveNonExpiringAgent {
            max: flags.contains_key("max"),
        },
        "serve-eth-rpc" => Command::ServeEthRpc,
        other => return Err(NodeError::Cli(format!("unknown subcommand: {other}"))),
    };

    Ok(CliArgs { chain, command })
}

type ParsedFlags = (HashMap<String, bool>, HashMap<String, String>);

fn parse_flags(rest: &[&str]) -> Result<ParsedFlags, NodeError> {
    let mut flags = HashMap::new();
    let mut values = HashMap::new();
    let mut i = 0;
    while i < rest.len() {
        let tok = rest[i];
        let Some(key) = tok.strip_prefix("--") else {
            return Err(NodeError::Cli(format!("unexpected positional arg: {tok}")));
        };
        if let Some((k, v)) = key.split_once('=') {
            flags.insert(k.to_string(), true);
            values.insert(k.to_string(), v.to_string());
            i += 1;
        } else if let Some(next) = rest.get(i + 1)
            && !next.starts_with("--")
        {
            flags.insert(key.to_string(), true);
            values.insert(key.to_string(), (*next).to_string());
            i += 2;
        } else {
            flags.insert(key.to_string(), true);
            i += 1;
        }
    }
    Ok((flags, values))
}

fn require_val(values: &HashMap<String, String>, name: &str) -> Result<String, NodeError> {
    values
        .get(name)
        .cloned()
        .ok_or_else(|| NodeError::Cli(format!("missing required option --{name}")))
}

fn parse_u64_validated(s: &str, name: &str) -> Result<u64, NodeError> {
    if !accepts_u64_decimal(s.as_bytes()) {
        return Err(NodeError::Cli(format!("invalid u64 for --{name}: {s}")));
    }
    let digits = s.strip_prefix('+').unwrap_or(s);
    digits
        .parse::<u64>()
        .map_err(|_| NodeError::Cli(format!("invalid u64 for --{name}: {s}")))
}

fn parse_bool_validated(s: &str, name: &str) -> Result<bool, NodeError> {
    if !accepts_lowercase_bool(s.as_bytes()) {
        return Err(NodeError::Cli(format!("invalid bool for --{name}: {s}")));
    }
    Ok(s == "true")
}

/// Format a `ReplicaStyle` back into its canonical node #115 CLI spelling.
pub const fn replica_style_str(style: &ReplicaStyle) -> &'static str {
    match style {
        ReplicaStyle::Actions => "actions",
        ReplicaStyle::ActionsAndResponses => "actions-and-responses",
        ReplicaStyle::RecentActions => "recent-actions",
    }
}
