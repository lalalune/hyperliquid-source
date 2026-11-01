# Commands and tools

All commands use the repository root unless stated otherwise. Only the newly
authored Rust client executes; no captured artifact, emulator, node, chain or
network service is run.

Initial static collection:

```sh
git fetch origin main
git switch -c research/node94-slot-restore-rust origin/main
python3 -O research/work-items/RE-001-slot-restore-rust-94/static_evidence.py --out research/work-items/RE-001-slot-restore-rust-94/static
```

The static script authenticates the whole target, resolves ELF sections, parses
all FDEs and relocations, and invokes these complete body exports:

```sh
/opt/homebrew/opt/binutils/bin/objdump -d --start-address=0x3290130 --stop-address=0x3290192 artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=0x3290130 --stop-address=0x3290192 artifacts/node/94/hl-node
/opt/homebrew/opt/binutils/bin/objdump --dwarf=frames artifacts/node/94/hl-node
```

GNU frame output is consumed incrementally and the full bound FDE/CIE records
are retained. Symbol labels from stripped-binary nearest-symbol arithmetic are
not treated as identity. `logs/tool-versions.log` gives exact tool versions.

Before Rust existed, the oracle was authored from the pointwise proof, then
frozen with `oracle.py --freeze`. A fixture review added 36 minimal-state
cases, still before any Rust existed, and repeated the freeze. Its chronology
is recorded in `logs/pre-rust-freeze-refinement.log`; the final oracle, inputs
and expectations remain immutable thereafter. Rust was then authored and
formatted. Complete native run:

```sh
python3 -O research/work-items/RE-001-slot-restore-rust-94/verify.py --out work/slot-restore/native-final
```

`native/commands.json` retains each actual compiler argv, working directory,
exit and output. Flags pin Rust 1.94.1, edition 2024, opt0/opt3,
codegen-units=1, overflow-checks=yes, panic=abort, debuginfo=0, warnings denied
and stable remapped build directories. Two independent builds per optimization
level are compared by rlib/executable SHA-256. Mutants are actual compiled
source variations, with normal-exit stdout compared to the same frozen oracle.

The archive is a deterministic gzip JSON with exact per-stream byte counts,
SHA-256 and labels, plus a shared dictionary of full lines and line-index lists.
Joining each list reconstructs original stdout including newlines. No output
values are recomputed or discarded in compression.

Global/focused replay commands are in README. Exact logs are retained. There
is no full test sweep, hosted CI, container execution or whole-node equality
claim. Only public read-only GitHub queries were used for live overlap checks.
