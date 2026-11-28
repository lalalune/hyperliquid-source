use std::process::{Command, Output};

use hl_node::cli::Subcommand;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hl-node"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn both_help_forms_select_each_of_the_fourteen_commands() {
    for sub in Subcommand::ALL {
        let name = sub.as_str();
        let long = run(&[name, "--help"]);
        assert!(long.status.success(), "{name}");
        assert!(long.stderr.is_empty());
        let short = run(&[name, "-h"]);
        let positional = run(&["help", name]);
        assert!(
            short.status.success() && positional.status.success(),
            "{name}"
        );
        assert_eq!(long.stdout, short.stdout);
        assert_eq!(long.stdout, positional.stdout);
        let text = String::from_utf8(long.stdout).unwrap();
        assert!(text.contains(&format!("USAGE:\n    hl-node [GLOBAL OPTIONS] {name} ")));
        assert!(!text.contains("SUBCOMMANDS:"));
    }
}

#[test]
fn snapshot_help_distinguishes_required_values_and_flags() {
    let help = run(&["--chain", "Local", "compute-l4-snapshots", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    for option in [
        "--abci-state-fln <VALUE> (required)",
        "--out-fln <VALUE> (required)",
        "--include-users",
        "--include-trigger-orders",
    ] {
        assert!(text.lines().any(|line| line.trim() == option), "{option}");
    }
    for unrelated in ["--wei", "--serve-info", "--validator"] {
        assert!(!text.contains(unrelated), "{unrelated}");
    }
}

#[test]
fn root_help_and_unknown_help_targets_stay_separate() {
    let root = run(&["--help"]);
    let positional = run(&["help"]);
    assert!(root.status.success() && positional.status.success());
    assert_eq!(root.stdout, positional.stdout);
    assert!(
        String::from_utf8(root.stdout)
            .unwrap()
            .contains("SUBCOMMANDS:")
    );
    let unknown = run(&["help", "absent"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stdout.is_empty());
    assert!(
        String::from_utf8(unknown.stderr)
            .unwrap()
            .contains("absent")
    );
}
