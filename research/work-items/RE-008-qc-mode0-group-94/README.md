# RE-008: mode-zero second QC group

This packet reconstructs the four accepted integer reads and first short-input
result at node94 `0x466bf60..0x466c13f`, under **u64(D+0)==0**. It closes the
mode-zero/non-FD composition gap left by #1509's mode1 FD-only group. It is not
yet published. The target is SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The captured executable was never executed or emulated.

## Native observations and premises

The second row call is `0x4c7e422 ->0x466bf60`; its result temporary is row-local
RSP+0x28. Four calls at `0x466bfbe/0x466c001/0x466c044/0x466c083` reach scalar
wrapper `0x466bd10..0x466bdf5`. The Reader dispatch is independently bound by
RELATIVE slot `0x57745e0 ->0x466d980..0x466dabc`. Complete row-owner context
is `0x4c7e340..0x4c7e60d`. Four FDE/CIE identities, complete body hashes,
dispatch tables, 462 instruction rows from both GNU and LLVM, six call edges
and mode guards are frozen in [pre-rust/](pre-rust/README.md).

The group and scalar wrapper's **DWORD** comparisons skip mode1 reservation
and charging. Three successful-prefix refunds instead test the **QWORD** mode
word. Under full-word zero all skip C/L loads and C stores. C and L may be any
u64, including C=MAX with L=0; there is no admission-budget condition here.

Accepted markers 0..FA, FB, FC and FD consume respectively 1/3/5/9 bytes and
produce unsigned immediate/u16/u32/u64 little-endian values. Nonminimal widths
are accepted. The wrapper selects fast reads at remaining N>8 and Reader at
N<=8; accepted successful values and cursor effects agree on those routes.
A complete FD necessarily takes the fast arm in this wrapper.

The first marked short consumes its marker and leaves its available payload
unread: FB/FC/FD need 2/4/8 minus available payload bytes. EOF before a marker
consumes nothing more and needs 1. Later group calls do not run after this
result. Only active error fields are recovered: group tag qword1, kind byte0,
need qword at +0x10. The retained shared row error corridor forwards them and
returns before recovery; the driver renders that projection separately.

Immutable input, writable decoder state/results, valid nonwrapping ranges,
ordinary returns/preserved registers and no external mutation are premises.
Ranges must not alias each other or the callee's own live preservation/control
machinery. Declared output temporaries in ancestor frames are allowed: group
G is row-local RSP+0x28, scalar output is group-local RSP+8.

## Independent Rust scope

`src/node94-consensus-admission/src/qc_mode0_group.rs` extends the genuine
existing consensus component. Cargo.toml and Cargo.lock are unchanged; this
bounded kernel uses standard-library LE conversions without new dependencies
or imported inferred source. Existing mode1 FD APIs remain byte-identical.

`read_mode0_group` exposes a chosen safe outcome and borrowed input suffix.
It checks the full mode word, qualifies markers only through the first short
or four completions, and does not inspect/update its charge/limit arguments.
Complete outcomes carry four ordered u64 words. Incomplete outcomes expose
only the active tag/kind/need projection. Atomic OutsideDomain for wrong mode
or FE/FF marker is a chosen API rule, with no assigned native outcome there.
Suffix/payload FE/FF bytes are not rejected as markers.

The input-only example receives five TSV columns over stdin. Expected outputs
are separate and never enter that driver. Native-derived fixtures were frozen
and independently reviewed **before** new Rust: 36 asymmetric successes,
56 marked short cases and 4 EOF cases. Small widths occur at all four positions
with exact remaining 8/9, plus mixed routes, nonminimal values and maxima.

## Validation and negative controls

Actual rustc/Cargo 1.94.1 builds at opt0/3 each match all **96/96** frozen rows.
Sixteen source/Cargo pins include all 13 library `.rs` files and the selected
example; actual dep-info names exactly those 14 compiler-read `.rs` files.
Every selected build uses a fresh empty target and must report compiling that
exact source root. Source snapshots, executables, dep-info and raw streams are
retained under ignored `work/qc-mode0-group/compare-fresh/` and hash-bound by
[RESULTS.json](RESULTS.json).

[RAW-TEXT.json](RAW-TEXT.json) durably retains the actual 26 compile/run streams
and dep-info, rejected stale-cache output, checker/failure logs, component and
repository checks, and local-input/cache-cleanup receipts. Its explicit path
allowlist excludes executables, libraries and source copies. Repeated text is
deduplicated by SHA-256. Each original byte string is exactly
`bundle["objects"][bundle["files"][path]].encode("utf-8")`; verify its SHA-256
against that path's digest before inspection. Canonical compiled/replay receipt
formatting is independently recoverable as documented in RESULTS.

Twelve compiled countermodels disagree in both profiles. Their full-corpus
mismatch counts are **Rust countermodel counts**, not predictions for every
patched-native execution. Each is separately required to reproduce its named
pre-Rust native witness prediction. The Reader32 countermodel also changes
immediate Reader values; the native MOVq-site mutation covers marked FB/FC
success only. Its qualified witness uses a previous FD to initialize the
temporary high word. The refund countermodel skips C<8, where the native
counterfactual reaches an underflow helper. No native patched binary was run.

| Countermodel | Differing rows per profile |
| --- | ---: |
|first refund applied|41|
|immediate fast width 2|8|
|FB/FC/FD fast widths 2/4/8|27 / 15 / 42|
|FB/FC Reader widths 2/4|5 / 14|
|FB Reader sign-extension|4|
|Reader narrow store with previous value|13|
|FB/FC/FD shortfall minus one|8 / 16 / 32|

Two validation failures are preserved and excluded from success claims:

- An initial shared Cargo cache reused the baseline executable for the first
  mutant despite relocating dep-info paths. The verifier rejected it. Fresh
  empty per-build targets resolved this; completed caches were removed only
  after archiving binaries/dep-info/raw streams.
- Review found that a word predicate could be skipped when actual words were
  absent. The exact successful executed comparator was preserved. The stronger
  checker requalified all 26 retained raw runs and rejected six missing-word
  corruptions. This was a **replay**, with no compiler or executable rerun.

Cargo all-targets tests pass **54/profile**, including all five examples.
The enclosing wrapper exited1 only after its post-release disk-reserve check;
both Cargo commands themselves exited0. Focused Python tests pass4/4, native
verification passes, and doctor/verify/catalogue-check/reproduce exit0. Initial
LFS-pointer check failures are retained: final repository checks followed local
identity-checked hardlink materialization after reflinks proved unsupported.
Source/target inode, mode and SHA receipts show no source-byte change. Only
authenticated local pinned inputs were used; no fetch or persistent setting
change occurred. Full root `make test` remains deferred to coordinator integration.

## Reproduction

Use an explicitly selected rustc1.94.1 and installed LLVM objdump:

```sh
python3 research/work-items/RE-008-qc-mode0-group-94/verify.py \
  --binary /path/to/authenticated/hl-node --llvm /path/to/llvm-objdump \
  --out work/mode0-native-new
python3 research/work-items/RE-008-qc-mode0-group-94/verify_rust.py \
  --rustc /path/to/rustc --out work/mode0-rust-new
python3 -m unittest discover -s tests -p test_qc_mode0_group94.py -v
cargo test --offline --locked --manifest-path src/node94-consensus-admission/Cargo.toml --all-targets
cargo test --offline --locked --manifest-path src/node94-consensus-admission/Cargo.toml --all-targets --release
```

## Credit and unfinished work

#1365 owns scalar wrapper/Reader semantics. #1526 composes a different response
helper. #1366 concerns outer error construction. #1509 supplies earlier group,
byte-field, row-assembly and first-short context; those historical packets are
unchanged. This packet claims the full-zero accepted-marker group composition.

Names/types are inferred descriptions. Original ABI/layout/lifetimes, mode
construction and complete QC-call reachability remain unproved, as do inactive
error bytes, instruction/store timing, unwind/panic ownership and cryptographic
validity. No captured execution, runtime equivalence, target-code byte match,
full QC implementation or completed component gate is claimed. All full gates
remain false.
