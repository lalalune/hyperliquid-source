# Source qualification plan — no compilation yet

Read SOURCE-PROOF and the immutable parent CONTRACT/PROOF first. The parent
pre-code gate authorized this bounded authoring phase. A separate exact
source/build gate is required before invoking build.py; version queries,
rustfmt and offline locked Cargo metadata are the only completed Rust-tool
preparation commands. preparation/commands.json retains all eight commands
and their unmodified stdout/stderr bytes. They do not establish test success.

The actual graph is the dependency-free node94-consensus-admission package:
13 admitted baseline files plus the new module and test. Eleven baseline files,
including Cargo.toml/lock and evidence_contract.rs, remain exact; lib.rs adds
one public module declaration and README adds one section. Removing those
insertions reconstructs the original hashes. All52 pre-code files stay exact.
The builder rejects source/harness symlinks, unexpected source files, hooks,
dependencies, lexical/canonical ancestor Cargo configs and ancestor workspaces.
Cargo metadata must report the copied component itself as workspace_root.
The old evidence_contract target is present and inspected but never selected.

TOOLCHAIN-PINS binds all97 installed bin/lib payloads of Rust1.94.1 for the
aarch64-apple-darwin host. The builder rehashes them before and after work,
creates a fresh CARGO_HOME, uses a minimal explicit environment, and retains
version/linker/selected SDK identities. HOME is preserved, never repurposed.
The complete host OS, loader and SDK are not hermetically reproduced. Before
the first compilation it replays the frozen static verifier; its only expected
receipt difference is the now-present pre-code freeze hash phase marker.

The first clean copy is built offline/locked in debug and release. In each
profile, explicit `cargo test --lib` selects36 existing pure library tests plus
two new private tests; `cargo test --test request_throttle` selects eight new
integration tests. Clippy selects only the library and that integration target.
No broad test command, captured target or instruction evaluator is invoked.
The client is linked directly against the exact produced rlib. Each full
949-history/3776-step stream must match the frozen expectations byte-for-byte.
The second clean copy has a genuinely distinct canonical directory and repeats
both profile value streams; raw rlib/client equality or inequality is recorded
without masks or normalization. No equality is assumed in advance.

MUTANTS.json binds20 exact textual module variants. Each must actually compile
and emit a complete canonical LF-terminated949-line stream in both profiles;
every line retains its original ID and complete step count. Eighteen mutants
must distinguish at least one of the934 native-conditional histories. The two
safe-policy mutants must distinguish at least one of15 new-policy histories
and zero native histories. A compile failure, malformed/partial output, or
surviving variant is a required-check failure, never a semantic kill.

The frozen explicit-delay inputs contain no exact multiplication-halfway case.
Thus there is no claim of a corpus-discriminated ties-even mutant. The universal
rounding proof in SOURCE-PROOF establishes ties-even; the finite corpus and
precision/direction mutants do not replace it. No corpus changes were made to
fit source or mutants. Native correspondence remains conditional on the frozen
memory, external-helper and floating-environment premises.

Ten comparator corruption controls challenge missing/extra/reordered IDs,
changed values, missing data and newline differences. Twenty malformed client
inputs derive from actual TH01 fields, including invalid initial state, duplicate
keys/reasons, options, counts and short/trailing data. An extra argument must
fail and empty input must succeed without output. Any malformed input batch
must fail before emitting a partial successful value stream.

The client has explicit transport policies: lowercase hex only; ASCII
alphanumeric/underscore/hyphen IDs of1..64 bytes;32MiB total input;2MiB decoded
frame;4096 initial rows/steps; steps*(initial+steps)<=1,000,000; and128MiB
accumulated output. These are adapter resource limits, not native domain limits.
They do not change the library's finite-state API. It buffers output until all
input lines validate; allocation failure remains excluded rather than rolled back.

The planned complete run has174 child commands,44 complete value streams,
22 source/client copies and88 first-compiled artifact identities. These are
planned denominators, not completed observations. Every command's stdout/stderr
is retained before checking its result. A launch error has empty child streams
and a separate retained harness exception diagnostic; a timeout retains the
partial streams available from the subprocess exception. Kill-before-launch,
host termination and unreported descendant effects are not claimed observed.
First produced rlibs are copied before tests; first clients before value runs.
Every subsequent source mutation has its own private copy. The harness stops
on the first required failure and does not rewrite source, corpus or freezes.

Public qualification will contain raw streams only after privacy inspection;
private compiled binaries and build paths remain private, with exact public
hashes and truthful availability limits. No runtime cache belongs in a public
manifest. Final measured results and any corrections must be additive records.
