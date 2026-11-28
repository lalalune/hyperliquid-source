# Command-scoped help in the node 115 CLI

`hl-node compute-l4-snapshots --help` on base commit `2da45cb0a761cff6b478e40421699857d87a94df` printed the root command list and hid both required paths and both optional flags. `hl-node help compute-l4-snapshots` exited 2. The reconstructed binary now directs the three help spellings to the selected command before checking its required values or executing any command. Required values carry a marker. Global help and command validation share the existing entry point. The parser and renderer use the same command-option tables.

## Target observations

The static input is the pinned node 115 Linux ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses are linked ELF VAs. A local GNU objdump decode across the unwind-described range `0x1637ae0..0x16382b7` places the following at instruction boundaries.

| Instructions | Observed data |
| --- | --- |
| `0x1637c55`, `0x1637c5c` | RIP-relative address of the 23-byte built-in help option description at `0x46cb8a` and its length. |
| `0x163801e` | Stores the four ASCII bytes for the generated command name `help`. |
| `0x16380dd`, `0x16380e4`, `0x16380ec` | Resolves the descriptor at `0x46cbd2`, stores its pointer, then stores length 58. It describes help for the given subcommands. |

The [command factory](../RE-012-node115-cli-command-factory/) supplies 14 child names and 24 local declarations. The [shared run-option builder](../RE-012-node115-cli-common-settings/) supplies 14 additional declarations on each of the two run commands. The raw declaration flags distinguish required values, optional values, and presence flags. The hidden run alias stays out of the child help. The three existing workspace-only run options (`--dry-run`, `--data-dir`, `--http-bind`) are also displayed on those two commands. The static verifier checks the pinned target, referenced descriptor bytes, instruction operands and containing FDE. It builds the independent Rust CLI and compares every scope and value/flag marker to the recovered registrations, including sets with no local options.

The short, long, and positional help routes implement the semantics indicated by these descriptors. Original help typography, wrapping, error messages, vendor version, full parser control flow and native runtime output equivalence remain unverified. The capture was read as a file. The node-runtime gate remains partial.

## Replay

Use an installed Rust 1.95.0 toolchain and Python 3. Run these commands from the repository root.

```sh
python3 -B research/work-items/RE-012-node115-cli-command-factory/verify.py
python3 -B research/work-items/RE-012-node115-cli-common-settings/verify.py
python3 -B research/work-items/RE-012-node115-command-help/verify.py
cargo test --locked --offline --manifest-path src/hl-node/Cargo.toml --test cli_and_workspace --test command_help
```

To repeat the failing comparison against the same descriptor set, use a fresh temporary directory. The base verifier is expected to exit 1.

```sh
base_tree="$(mktemp -d)"
git archive 2da45cb0a761cff6b478e40421699857d87a94df src | tar -x -C "$base_tree"
python3 -B research/work-items/RE-012-node115-command-help/verify.py --source-tree "$base_tree"
```

[Observed output](validation.txt) includes exact before/after counts. The [eight-second terminal comparison](terminal.mp4) displays the two binaries' captured stdout/stderr and exit status for `help compute-l4-snapshots`.
