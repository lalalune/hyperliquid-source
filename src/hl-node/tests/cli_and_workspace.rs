use std::process::Command;

use global_constants::ChainName;
use hl_node::cli::{CliAction, CliError, Subcommand, parse_args};
use hl_node::wiring::workspace_health;
use node115_startup_output::ReplicaStyle;

#[test]
fn cli_parses_all_14_node115_subcommands_and_aliases() {
    assert_eq!(Subcommand::ALL.len(), 14);

    let act = parse_args([
        "--chain",
        "Testnet",
        "run-non-validator",
        "--serve-eth-rpc",
        "--serve-info",
        "--write-trades",
        "--replica-cmds-style",
        "actions-and-responses",
        "--dry-run",
    ])
    .unwrap();
    let CliAction::Command(cmd) = act else {
        panic!("expected command");
    };
    assert_eq!(cmd.chain, ChainName::Testnet);
    assert_eq!(cmd.subcommand, Subcommand::RunNonValidator);
    let settings = cmd.output_settings.unwrap();
    assert!(settings.serve_evm_rpc);
    assert!(settings.serve_info);
    assert_eq!(settings.replica_style, ReplicaStyle::ActionsAndResponses);

    let vp = parse_args([
        "change-validator-profile",
        "--abci-state-fln",
        "/tmp/state.rmp",
        "--node-ip",
        "10.0.0.1",
        "--commission-bps",
        "+250",
        "--disable-delegations",
        "false",
        "--unjailed",
    ])
    .unwrap();
    let CliAction::Command(vp_cmd) = vp else {
        panic!("expected validator profile command");
    };
    assert_eq!(vp_cmd.subcommand, Subcommand::ChangeValidatorProfile);
    assert!(vp_cmd.flags.contains("unjailed"));
}

#[test]
fn cli_rejects_invalid_node115_validator_inputs() {
    assert_eq!(
        parse_args([
            "change-validator-profile",
            "--abci-state-fln",
            "/tmp/s",
            "--node-ip",
            "999.0.0.1",
        ]),
        Err(CliError::InvalidNodeIp("999.0.0.1".to_string()))
    );
    assert_eq!(
        parse_args(["staking-deposit", "--wei", "-10"]),
        Err(CliError::InvalidU64 {
            option: "wei",
            value: "-10".to_string()
        })
    );
    assert_eq!(
        parse_args([
            "change-validator-profile",
            "--abci-state-fln",
            "/tmp/s",
            "--disable-delegations",
            "True",
        ]),
        Err(CliError::InvalidBool {
            option: "disable-delegations",
            value: "True".to_string()
        })
    );
    assert_eq!(
        parse_args([
            "run-non-validator",
            "--replica-cmds-style",
            "invalid-style"
        ]),
        Err(CliError::InvalidReplicaStyle("invalid-style".to_string()))
    );
}

#[test]
fn workspace_health_links_all_26_first_party_crates() {
    let h = workspace_health(ChainName::Mainnet);
    assert_eq!(h.chain, "Mainnet");
    assert_eq!(h.api_url, "https://api.hyperliquid.xyz/");
    assert_eq!(h.bridge_cid, "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7");
    assert_eq!(h.linked_subsystems.len(), 26);
}

#[test]
fn compiled_hl_node_binary_runs_offline_version_help_and_dry_run() {
    let bin = env!("CARGO_BIN_EXE_hl-node");

    let ver = Command::new(bin).arg("--version").output().unwrap();
    assert!(ver.status.success());
    assert_eq!(String::from_utf8_lossy(&ver.stdout).trim(), "hl-node 0.1.0");

    let dry = Command::new(bin)
        .args([
            "--chain",
            "Mainnet",
            "run-non-validator",
            "--serve-eth-rpc",
            "--replica-cmds-style",
            "recent-actions",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(dry.status.success());
    let stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(stdout.contains("chain=Mainnet"));
    assert!(stdout.contains("replica_style=recent-actions"));
    assert!(stdout.contains("serve_evm_rpc=true"));
    assert!(stdout.contains("subsystems=26"));

    let bad = Command::new(bin).arg("no-such-command").output().unwrap();
    assert_eq!(bad.status.code(), Some(2));
}
