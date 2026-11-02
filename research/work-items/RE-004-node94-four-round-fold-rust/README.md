# RE-004: four-round multiply/carry leaf with arbitrary-input folds

This packet reconstructs the complete node #94 leaf
`[0x565d8a0,0x565da24)` in independently authored no_std Rust. Its gap was the
unresolved relation between four low-word coefficient products, sixteen
unsigned full-width products, four low/high folds, and the final register
values. The result admits every nine-word numeric input without assuming an
inverse or modulus. No progress gate changes are requested.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base source commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Component: bounded arithmetic helper under RE-004. Addresses are original ELF
VAs; no normalization masks are used. Imported references and submodule pins
are unchanged; no unlicensed implementation was read or copied.

## Established relation and boundaries

`PROOF.md` derives all four rounds and the exact nine-register result for the
whole numeric domain. A noteworthy instruction detail is ADC adding the high
product to an accumulator that already contains the low-product sum. Its
carry is then overwritten by the next MUL. An ordinary cancellation-reduction
formula would lose this behavior on arbitrary input; neither that formula nor
its usual inverse precondition is presumed here.

`static-lock.json` pins the complete leaf, both complete direct-caller contexts,
and each actual FDE/CIE record. Capstone decodes all 388 leaf bytes into 115
instructions, including the two-byte return. Independent GNU exports and frame
records are retained. Both E8 candidates are boundary-qualified at `0x565d785`
and `0x565d825`; the E9 and EB pattern scans have no hits. There are no leaf
branches, calls, stores, RIP-relative arithmetic constants or data-table edges.
All 80,300 RELA records are scanned for naming addends and overlapping writers;
none name the entry or write the claimed/context body windows or padding.
This is not a complete whole-program cross-reference census.

The safe API takes snapshots of both four-qword input windows and entry RCX.
Stable successful target reads are a stated premise. Aliased input windows
are admissible because this leaf never writes memory. Pointer faults, racing
storage, flags, stack control and the original register ABI are excluded.
The caller bodies establish two observed direct edges and register setup only;
their alternate branches and post-call arithmetic are not reconstructed here.

## Independent expectations and native qualification

`oracle.py` first admitted the full target digest, body/FDE/memory/relocation
closure, then froze 23,980 cases before the Rust directory existed. It uses
whole 256-bit integer sums, division and a discarded-fold correction. The Rust
uses four u128 limb products with bounded carry convolution. Their algebraic
equivalence is proved separately in `PROOF.md`; neither executes or emulates
captured instructions. `frozen/ORACLE-FREEZE.json` records the UTC freeze,
source hash, compressed-fixture raw hashes and all static facts.

Fixtures include every bit boundary in every input/operand lane, homogeneous
and complementary extreme patterns, all-zero/all-ones cases, coefficient high
bits, coefficient multiplication wrap, and 4,096 seeded arbitrary cases.
The four rounds have respectively 1,936 / 2,376 / 2,645 / 3,128 cases where the
low-fold overflow is discarded. All nine output registers are compared.

The installed rustc 1.94.1 compiler is pinned by release, commit and actual
executable SHA-256. The macOS arm64 native runs use opt levels 0 and 3, each
built twice, with overflow checks, panic abort and warnings denied. Every build
matched all 23,980 frozen expected tuples: 95,920 successful comparisons.
Each same-optimization rebuild has identical library, client and output hashes.
These are new native Rust executions, not Linux target executions or
machine-code equivalence measurements.

Sixteen compiled wrong variants all completed and produced mismatches, including
omitted or saturated folds, shortened iteration count, coefficient width/wrap,
upper carry loss, reversed operand lanes and incorrect final register mappings.
Mismatch counts and actual input/expected/observed counterexamples are retained
in `observed/results.json` and `selected-controls.json`. All 31 structural
corruptions were rejected. A deliberately corrupted expectation produces
exactly one comparison mismatch; malformed client input exits 2 without stdout.

`observed/raw-streams.json.gz` losslessly retains 134 original stdout/stderr
streams, with command labels and SHA-256 values. Repeated native stdout uses
XOR against the first stdout before base64 encoding; this is storage encoding,
not output normalization. `verify_recorded.py` reconstructs every exact stream,
checks all hashes and command exits, recounts native mismatches, and verifies
the selected counterexamples. The large GNU frame stdout is explicitly retained
as selected original CIE/FDE records; it is not described as a complete raw
frame dump. Readable disassembly removes only line-ending whitespace; the exact
GNU stdout remains in the archive.

## Reproduce and remaining scope

From repository root, using installed Python 3.14.3, Capstone 5.0.7, GNU
binutils 2.47.20260726, and rustc 1.94.1:

```sh
python3 -O research/work-items/RE-004-node94-four-round-fold-rust/validate.py \
  --output work/node94-four-round-fold/recheck
python3 -O research/work-items/RE-004-node94-four-round-fold-rust/verify_recorded.py
shasum -a 256 -c research/work-items/RE-004-node94-four-round-fold-rust/MANIFEST.sha256
```

The validator regenerates and byte-compares the frozen fixtures, rechecks the
original static bytes, and builds only the new Rust sources. It refuses any
changed frozen oracle. Exact command arguments, compiler identity and output
hashes are in `observed/commands.json` and `results.json`.

Local `make doctor verify catalogue-check reproduce`, 24 focused ELF/FDE/GNU
cross-check tests, rustfmt checks and the archive audit passed. Their raw output
is retained in `observed/repository-checks.json.gz`. The shared baseline sweep
reported 971 files / 15,462 tests / 69 skips; its original make exit was 2 due
only to three disk-full errors, and all 20 affected tests passed isolated
retries. That shared baseline is not a new full suite on this branch or Linux
qualification. No hosted CI result is claimed.

No node-wide ABI/build equivalence, mathematical operand meaning, complete
caller family or progress gate is established. A remaining bounded question is
which constraints the callers impose on the coefficient and operand; this
packet's arbitrary-input relation does not depend on answering it.

Authorship: OpenAI / Codex client; the exact runtime model identifier is not
exposed to this session and is not invented.
