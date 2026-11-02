# RE-014: independently authored Rust for node115 snapshot selector prefixes

> Current #115 migration (2026-11-02): this implementation was rebuilt and
> compared at opt-level 0 and 3 after retiring the older node and trimming
> its shared tooling. `migration-validation.json` records the fresh run and
> compiled mutation controls. Historical blocker reports below describe the
> original environment; they do not require the retired binary. Original
> negative results and target-bound records remain unchanged.


Component: info-server snapshot preparation / release-specific reconstruction.
Target node115, 105896032 bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `e5c9b6436876b2a4a39daef813171f9879317699`; freeze `d20080a8`.
Credit merged #998 and the unchanged RE-001-node115-snapshot-selection packet.
That packet establishes these raw routes but supplies no Rust implementation.
No claim is made about node94, an integrated node, original request types or ABI.
New Rust and comparison code are independently authored MIT; no inferred
unlicensed source or native instruction bytes are transplanted into Rust.

## Measured scope

All addresses below are original ELF virtual addresses, not provider rebases.
The accepted packet retains seven complete FDEs, 9917 bytes / 2057 instructions,
full original GNU exports, body hashes, source Locations, direct calls and
relocations. Its immutable spec and regenerated full records are checked before
this comparison. `native-records.json` reproduces those records exactly.
The new evaluator measures only 90 selected instructions inside those owners,
not all 2057 instructions or whole-function behavior.

Four workers begin at 0x22b6490, 0x22b6cd0, 0x22b7510, 0x22b7d50. Selected
prefixes at relative +0x19 and +0x474 classify word 0x8000000000000000 as the
all-collection prefix; other words compare the raw qword at input+16 unsigned
against 101. Values >=101 select the limit-exit prefix, others explicit selection.
These are branch classifications under qualified readable input, not complete
collection construction, a response-size cap or an API-policy bypass.

Wrappers 0x273bb10 and 0x273bd20, starting at +0x14, normalize **R8d**, not R8,
to 0/1. Their distinct special word is 0x8000000000000001. Other words dispatch
using the entire byte at input+0x1a: wrapper0 nonzero/zero -> worker0/2;
wrapper1 nonzero/zero -> worker3/1. Context+0x28 is an opaque initialized qword;
no concrete context schema is invented. Evaluation stops before any callee.

Each worker's +0x43b selected prefix compares the saved qword mode to exactly1.
Other mode words classify as unequal; downstream callback effects remain open.
The 0x2308124 selected exit-helper guard reaches the known epilogue for raw u16
tags266..351. The complementary class is **OtherUnclosedRoute**: it does NOT
mean that a call occurs or that those tags cannot return. For example tag0 also
returns on a later unmeasured route. Prologue, epilogue and other helper paths
are not reconstructed by this classifier.

## Active blocker and smallest local remedy

The existing integer evaluator's `decimal_scaled_u64.Image(node115)` actually
raises KeyError0x576f488: its constructor binds node94-specific diagnostic slots.
The packet records this before production code. The local image adapter parses
only real node115 sections/FDEs/relocations, borrowing generic read/decode methods.
It invents no slot, panic callback or target stub and changes no shared evaluator.
Its Machine rejects every call, restricts instruction regions and step count,
and permits writes only to its 256-byte synthetic stack. Input/context roles
are read-only 64-byte regions. This is an offline Python instruction evaluation,
explicitly authorized by the operator; no captured process, Unicorn, filesystem
probe, live request, wallet, chain action or network execution occurs.
The runner is limited to unblocking and comparing this Rust family.

## Freeze, corpus and real compilation

FREEZE.json and 24 smoke rows were committed before production Rust. The native
instruction routes and independent scalar equations agreed before Rust existed.
The 189952 line-distinct rows include owner metadata, so they are NOT 189952
distinct logical Rust states:

- Worker: 108968 rows = 27242 raw selector/count pairs across four workers.
  257 words near zero, the overflow sentinel and u64::MAX; 106 counts including
  0..102, signed boundary and u64::MAX.
- Wrapper: 15420 rows =257 words *5 byte values *6 mode words *2 wrappers.
- Mode:28 rows =7 raw mode words across4 workers.
- Exit:all65536 raw u16 tags;86 known-positive, others explicitly unclosed.

`selected-instructions.json` retains raw bytes and lengths for all90 visited
instructions, independently decoded with Capstone5.0.6. The original static
producer also binds complete owners/calls/relocations/FDEs. Six private actual
instruction-byte edits change observed outcomes and are rejected by the old
static bindings; `native-controls.json` retains their operands and results.
No normalization mask is applied to comparison outputs or instruction operands.

Actual pinned rustc1.94.1 (e408947bfd200af42db322daf0fadfe7e26d3bd1), LLVM21.1.8,
macOS aarch64 host, builds standalone no_std rlibs directly. No Cargo workspace,
new dependencies, fabricated lockfile or placeholder node is added. Separate
input-only clients link each opt0/opt3 library; each matches all189952 outcomes.
The 24-row compiled smoke passes. Six real compiled mutants produce
848/1024/5140/6144/20/1 mismatches and all fail compiled smoke (exit101).
Own opt3 same-basename rlibs rebuild raw-identically without normalization;
this does not establish original x86-64 machine-code or ELF identity.

Build completed exit0 in245.415wall seconds under serial10% active wall-time
duty; native freeze completed exit0 in128.883wall seconds. This duty cycle is
not a guarantee of exact aggregate CPU percentage. OS setpriority is unavailable;
no nice19 effect is claimed. No parallel workers or duplicate checkout are used.

## Reproduce and validation limits

From the repository root with materialized authenticated captures, Python3.12.14,
GNU binutils2.47.20260726 and actual pinned Rust tools on PATH:

    python3 tools/node115_snapshot_selectors_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_node115_snapshot_selectors_rust tests.test_snapshot_selection_static.SnapshotSelectionTests.test_neg_overflow_selector_and_unsigned_count_boundaries tests.test_snapshot_selection_static.SnapshotSelectionTests.test_public_identity_gate_precedes_outputs -v
    "$RUSTFMT" --check --edition 2021 src/node115-snapshot-selectors/lib.rs src/node115-snapshot-selectors/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node115-snapshot-selectors/lib.rs --emit=metadata -o /new/lib.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node115-snapshot-selectors/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

Output must be new. The entire input/output corpus is authenticated against
FREEZE before compiler invocation. Raw full rows and compiler products regenerate
outside Git; build-result.json records commands and hashes, replacing only
private path spellings by $REPO/$OUTPUT/$RUSTC. Original static evidence, negative
results and source pins are untouched. Shared signed-input/import/inventory
checks reuse completed #1831 results only for explicitly checked unchanged paths;
see shared-input-validation.json. This reuse is not verification of new code.
Fresh focused/style/catalogue outcomes are recorded in validation-results.json.
Full make test has not completed and awaits upstream CI; queued is not PASS.

All full component gates, byte-credit registry and catalogue inputs remain
unchanged. Original ABI/layout, callback ownership, collection contents, complete
request/serialization/effects, helper closure, unwind and whole-node behavior
remain unresolved. Next close the selected collection helper and callback
before integrating an actual source-built snapshot request.
