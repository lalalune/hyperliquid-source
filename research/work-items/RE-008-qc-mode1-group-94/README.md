# RE-008: mode-one reservation and accepted-marker group

Node94 target SHA256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The bounded question is the full-word-one path at group
`0x466bf60..0x466c13f` (FDE`0xef1f28`), conditional on second row call
`0x4c7e422`. Coordinates are linked ELF VAs, ends exclusive. Captured binaries
are only read as data; none is executed or emulated.

## Gap and acceptance criteria

#1509's prior mode1 FD-only APIs leave nonadmitted states and non-FD markers
outside the native claim. Atomic refusal cannot describe the native over-limit
path: it stores C+32 before denying the limit. Four immediate values also
consume4 wire bytes while the group charges32. This packet extends that
contiguous group-state contract; it does not add a generic codec or claim
complete QC decoding.

Acceptance requires independent pre-source review of the native domain and
frozen128 cases, compiled Rust comparisons at opt0/3, exact source closure and
operative group countermodels. Initial denial must preempt marker errors;
overflow and limit failures must retain different charge states. Denial need
and inactive error meanings remain unspecified. Full component gates stay false.

## Observed native state

- Domain: all eight bytes at D+0 encode1. At `0x466bf74`, DWORDmode1 selects
  reservation. Other complete mode words remain outside this claim.
- `0x466bf7d/81` rejects unsigned C>MAX-32 before reading L or changing C.
  Otherwise `0x466bf8f` stores C+32 **before** `0x466bf93/96` checks C+32<=L.
  An exceeded limit retains the increment. Neither denial reaches a scalar
  or reads input pointer/length/marker; EOF or FE/FF cannot preempt it.
- `0x466bf98/9c` writes G tag qword1 and kind **byte**2. Only those nine
  bytes are initialized. Given a valid supplied prefilled40-byte G, the other
  31 bytes are unchanged. This is a raw memory relation, without payload/need
  meaning or recovered error ABI. Row code later copies G+0x10 anyway; that
  copied qword is not assigned a semantic need value here.
- On admission `0x466bfae/b2` sets state to originalC+24, using originalRAX.
  Each credited scalar charges8; each of the first three successful returns
  refunds8. Every scalar return therefore retains originalC+32, and before
  a next scalar state is originalC+24. Initial admission guarantees no scalar
  charging overflow/limit failure on the selected ordinary path.
- Accepted0..FA/FB/FC/FD values, widths1/3/5/9 and short/EOF cursor/need
  behavior are separately credited. This packet composes them under mode1.
  All four call/stop edges, complete wrapper/Reader/row contexts, FDE/CIE,
  dispatch and relocation bindings remain pinned in [pre-rust/](pre-rust/PLAN.md).

Input is immutable; decoder/results are mutable and valid. Nonwrapping ranges
are disjoint from each other and the callee's own live control/preservation
frame, with ordinary returns and no external mutation. Declared ancestor-frame
temporaries are permitted: G is row-local RSP+0x28. A mode constructor, native
source enum, object lifetime and complete QC-call reachability are not inferred.

## Independent Rust projection

`qc_mode1_group.rs` extends the existing genuine consensus crate without
changing its manifest/lockfile/dependencies or old mode0/FD APIs. It reuses our
separately proved mode0 value/cursor kernel as a safe-code implementation choice;
the native mode word is not claimed to change. Initial budget checks precede
that kernel. Admitted unsupported markers are a chosen atomic OutsideDomain;
their native behavior is unqualified. Budget failures accept arbitrary input
bytes without parsing them.

BudgetDenied exposes tag1/kind2 and **None** need. Complete exposes four words;
Incomplete exposes only its active short fields. `write_result_view` covers
full40-byte success or the initial denial's nine writes/31 preserved bytes.
It provides no raw incomplete-error image. Its false/no-buffer-write result
for unsupported views is a chosen safe API behavior, not target semantics.
The source projects final state, without native intermediate store timing.

The input-only example receives state, wire bytes and G's pre-state on stdin.
Expected outputs remain separate. Row error forwarding is driver-only active
field projection, with no denial need or full row-decoder implementation.

## Frozen validation scope

The accepted pre-source freeze is SHA
`5fa1a8a08792fda65f42923033315ed16533ce8d51755bd01fd67c945c97e209`:
96 admitted mixed-width/short cases (18 credited FD domains),24 initial denials
and8 exact-admission edges. It distinguishes C=MAX-32/MAX-31, inclusive L,
retained over-limit charge, arbitrary invalid-prefix/EOF precedence, each scalar
position and asymmetric supplied memory. Successes define the full result;
shorts define active fields only; initial denial memory has an explicit prefill.

Ten frozen static-site controls cover guard equality, reservation store/size,
initial24, each refund, tag and kind. Compiled source counterparts must reproduce
their named native witness predictions. Full-corpus counts are Rust countermodel
disagreements, not universal patched-native predictions. Refund counterparts
model only an extra8 that fits but exceeds L after k complete prefix reads;
other counterfactual states and inactive error bytes remain unqualified.

`verify.py` reauthenticates new anchors and all128 frozen states, then credits
the prior complete4-body/FDE/dual-tool collector. Its old mode0 checks are
context, not a new mode1 execution oracle. `verify_rust.py` uses fresh empty
Cargo targets, records actual compiler-read dep-info, and retains exact source,
executable and raw-stream identities. A missing success value/memory or an
API-only refusal cannot satisfy a native witness predicate. Actual compiled
results and durable raw receipts must be recorded before publication.

## Actual results and reproduction

Pinned rustc/Cargo1.94.1 selected-example builds match **128/128 at opt0 and
opt3**. Each of22 fresh builds has exact actual dep-info closure over **15 Rust
sources** (14 library modules plus the selected example), with17 source/Cargo
pins. Ten compiled countermodels differ on21,71,12,120,104,24,24,43,36,28 rows
per profile; every named native witness predicate passes. These totals remain
Rust countermodel counts. In particular changing the source reservation size
also changes its final admitted charge, whereas the single native LEA mutation
does not change the later originalC+24 setup. Refund countermodels do not
recover a patched generic-error memory image. Only the separately frozen
named-witness fields are compared with their native analytical predictions.

Cargo all-targets passes57 tests in each profile and builds all six examples.
Focused Python passes4/4. Native128-state/10-site verification and credited
4-body/FDE/dual-tool authentication pass. `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` all exit0. Full root `make test`
remains deferred to coordinator integration. No compiler/native/check failure
occurred in this phase; older failures remain in their unchanged packets.

[RESULTS.json](RESULTS.json) binds current source, executed checker, tools and
the compact [compiled receipt](execution/COMPILED.json). Original canonical
receipt bytes are reconstructed with the recorded JSON formatting. The actual
22 compile/run streams and dep-info, source-hash freeze, component/repository/
native/focused logs and resource-cleanup receipts are retained losslessly in
[RAW-TEXT.json](RAW-TEXT.json). For a named file, encode its SHA-keyed object as
UTF-8 and verify that digest: `bundle["objects"][bundle["files"][path]].encode("utf-8")`.
The allowlist excludes executables, libraries and source copies; those compiled
executables and immutable snapshots remain in ignored work for peer review.

Fresh targets, incremental0 and stripped debug-info-free binaries kept each
build above the300MiB floor, with316MiB required before a build. Completed
mode1 library/fingerprint caches and a separately completed published-mode0
Cargo target were removed only after hash inventories and preserving required
logs/receipts/selected binaries. Those resource actions are recorded; no source,
capture, installed toolchain or active target was changed.

```sh
python3 research/work-items/RE-008-qc-mode1-group-94/verify.py \
  --binary /path/to/authenticated/hl-node --llvm /path/to/llvm-objdump \
  --out work/mode1-native-new
python3 research/work-items/RE-008-qc-mode1-group-94/verify_rust.py \
  --rustc /path/to/rustc-1.94.1 --out work/mode1-rust-new
python3 -m unittest discover -s tests -p test_qc_mode1_group94.py -v
cargo test --offline --locked --manifest-path src/node94-consensus-admission/Cargo.toml --all-targets
cargo test --offline --locked --manifest-path src/node94-consensus-admission/Cargo.toml --all-targets --release
```

## Credit and remaining scope

#1365 owns scalar wrapper/Reader charging and cursor behavior; #1366 owns
outer error construction at4752890; #1509 supplies mode0 accepted markers,
mode1 admitted FD paths, recovery byte and assembly. #1526 composes a different
response helper. Those established facts are dependencies, not new byte credit.

Admitted FE/FF, other mode words, inactive short-error bytes, allocator/panic
ownership, original ABI/layout/lifetimes, constructor and full QC reachability,
cryptographic effects, runtime equivalence and target-code byte matching remain
open. No component gate or full repository-suite completion is claimed.
