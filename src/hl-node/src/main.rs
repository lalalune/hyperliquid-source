#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use hl_node::cli::{CliAction, Subcommand, command_help_text, help_text, parse_args, replica_style_label};
use hl_node::engine::NodeEngine;
use hl_node::wiring::workspace_health;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(args) {
        Ok(CliAction::Help) => {
            print!("{}", help_text());
            ExitCode::SUCCESS
        }
        Ok(CliAction::CommandHelp(sub)) => {
            print!("{}", command_help_text(sub));
            ExitCode::SUCCESS
        }
        Ok(CliAction::Version) => {
            println!("hl-node {}", hl_node::cli::VERSION);
            ExitCode::SUCCESS
        }
        Ok(CliAction::Command(cmd)) => {
            let health = workspace_health(cmd.chain);
            if cmd.subcommand.uses_common_run_options() && cmd.flags.contains("dry-run") {
                let settings = cmd.output_settings.as_ref().expect("run output settings");
                if let Some(dir) = cmd.values.get("data-dir") {
                    match NodeEngine::open_or_restore(cmd.chain, Path::new(dir)) {
                        Ok(eng) => {
                            println!(
                                "hl-node {} dry-run ok: chain={} subcommand={} replica_style={} serve_evm_rpc={} serve_info={} subsystems={} height={} abci_root={}",
                                hl_node::cli::VERSION,
                                health.chain,
                                cmd.subcommand.as_str(),
                                replica_style_label(&settings.replica_style),
                                settings.serve_evm_rpc,
                                settings.serve_info,
                                health.linked_subsystems.len(),
                                eng.latest_height(),
                                eng.abci_state_root_hex(),
                            );
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("error: checkpoint restore failed: {err}");
                            return ExitCode::from(4);
                        }
                    }
                }
                println!(
                    "hl-node {} dry-run ok: chain={} subcommand={} replica_style={} serve_evm_rpc={} serve_info={} subsystems={}",
                    hl_node::cli::VERSION,
                    health.chain,
                    cmd.subcommand.as_str(),
                    replica_style_label(&settings.replica_style),
                    settings.serve_evm_rpc,
                    settings.serve_info,
                    health.linked_subsystems.len(),
                );
                return ExitCode::SUCCESS;
            }
            match cmd.subcommand {
                Subcommand::RunNonValidator | Subcommand::RunValidator => {
                    eprintln!(
                        "hl-node: parsed {} for chain={} ({} linked subsystems); live P2P/sync loop requires --dry-run offline mode until node-runtime/exchange/evm loops finish wiring",
                        cmd.subcommand.as_str(),
                        health.chain,
                        health.linked_subsystems.len(),
                    );
                    ExitCode::from(3)
                }
                other => {
                    eprintln!(
                        "hl-node: validated arguments for {} (chain={}); offline execution only — live network/signing actions are disabled",
                        other.as_str(),
                        health.chain,
                    );
                    ExitCode::from(3)
                }
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}
