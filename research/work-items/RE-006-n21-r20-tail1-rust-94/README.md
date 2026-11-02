# RE-006: fixed n21 first-run20/tail1 normal values

## Gap and qualified result

This closes one neighboring value path left by #1524's first-short-run admission:
original unsigned A21 whose first native natural run is **exactly20**. Under
the stated node memory/frame premises, normal returns, and an ordinary external
nonoverlap `memcpy` contract, the core normalizes its first20 words, passes its
one-word tail through the no-access delegate return, and backward-merges all21
words. Final A preserves the original raw-u64 multiset in nondecreasing order;
S0 is the original tail and the remaining scratch is unchanged under the copy
contract. This is not all initial run11..20 cases, generic sorting or a full
component gate. No distinct element identity or tie stability is claimed.

Target node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Coordinates are half-open linked ELF VAs. Four complete
body/FDE/CIE bindings cover wrapper/core/adapter/delegate (4340B/1112 instructions).
Their existing full GNU/LLVM exports are reused from predecessor ec71facb, not
duplicated or counted as newly recovered bodies. #1455's reversal machinery and
#1430/#1524 predecessors are credited.

## Native route and actual external boundary

The core's threshold is11. Initial run20 bypasses fallback before reversal;
ascending20 is already nondecreasing, strict descending20 reverses via two SIMD
iterations plus swaps(8,11)/(9,10). Delayed previous markers1/41, current3 and
priorities2/1/sentinel0 force exactly one20+1 merge. Both markers are odd, so
lazy re-sort calls are skipped; merged marker43 then selects normal return.

Tail count1 passes core→adapter→delegate; delegate `0x4918d3f` returns before
any A/S access or capacity check. The backward merge copies A20 to S using8
bytes, shifts the strictly unsigned-greater suffix and either consumes the tail
or copies its last8 bytes after left exhaustion. The final call is present even
when its count is0. Equality loads output bits from left while retiring the tail
cursor. Those separate operands are observations, not recoverable element IDs.

Copy slot `0x576dfe0` is **GLOB_DAT dynsym6, undefined memcpy@GLIBC_2.14 from
libc.so.6**, not a local helper/FDE. The actual runtime provider/interposition,
its implementation, stack frame, faults and ABI identity are unknown. We assume
ordinary selected0/8-byte nonoverlap copies, requested-destination-only writes
and call preservation. No target bytes establish the provider's behavior.

Require stable valid nonwrapping A21, actual scratch and ordinary nonfaulting
calls. A avoids the entire node-owned `[S−0x3e0,W+8)` live span, S=W−0x1028.
S intentionally occupies the designated wrapper scratch `[S,S+0x1000)` inside
that span and avoids the other control/preservation slots. A and S are mutually
disjoint; both avoid the actual provider's live machinery, whose numeric lower
bound is unknown. The Rust docs' live-frame exclusion refers to control and
preservation storage, allowing the designated ancestor-frame scratch. Allocator
ownership/freshness remains unknown. Wrapper capacity is512, while this path
logically touches only S0. The safe API's initialized scratch prefix4 is a chosen
value view, not a physical512-word measurement.

## Rust and frozen comparison denominators

The independently authored `n21_run20_tail1` extends the existing dependency-free
orderbook crate, reusing its established unsigned natural-run scan. It admits
only exact run20, normalizes first20 and implements the backward value/cursor
relation. Copies are logical value operations, not execution of the target or
its imported libc. Returned arrays/indices/providers/copy counts are chosen
observations, not an original type/return ABI or measured compiler store trace.
Other run lengths refuse without changing arrays by explicitly chosen API policy.

Before source, froze48 qualified full-array cases: every ascending insertion
rank0..19 and descending rank1..20, plus8 duplicate/high-bit/tie cases. Six
mathematical exclusions become separately labeled safe-API policy cases.
Each frozen output has235 qwords plus chosen status, including final A21/S4,
post-normalization A21 and logical cursor/store/copy observations. Expected
full arrays use independent unsigned mathematical ordering; native rank formulas
and ordered stores/copies agree. Inputs carry no expected values.

Official Rust1.94.1, edition2024, warnings denied and overflow checks enabled:

- Four runs (opt0/3 twice) exactly match54 records each: **192 qualified native-
  derived comparisons plus24 policy comparisons**, not216 native cases.
- All46 component tests pass in each direct optimization profile. No new Cargo,
  full repository-suite, target runtime or hosted-CI success is claimed.
- Ten source controls compile/run atopt3 only. Seven have actual final A21
  array witnesses: omit reversal23,
  reverse18only23, wrong copied word47, signed merge1, choose-min48, truncate5,
  omit terminal8-copy2. Three controls preserve arrays and change only chosen
  provider/cursor/zero-copy observations (6/6/46 cases).

The conservative18-file compiler snapshot includes the exact ec71 component plus
one module/export, driver and duplicate candidate source. Thirty raw `.d` receipts
bind observed local dependencies:12 production Rust files,13 in tests, and the
driver. This is not exhaustive compiler/sysroot or dynamic-provider identity.
Compiler version/digest and the official installation receipt are recorded.

## Guard stop, honest resume and two preserved plan errors

The original guard completed only compiler-version and opt0 library commands,
then stopped **before** client build:348016640 bytes free was110592 below its
unchanged332MiB build preflight. No client/unit/mutant had run. Source, partial
library, `.d` and raw channels were preserved. After serialized checks finished
and space cleared, the resume verified exact original argv/raw/library/source/
wire hashes and reused those two actual commands; **45 unfinished commands ran**.
The47-slot qualification is explicitly phased, not47 new commands or a clean
initial attempt. The old enforced start compiler digest was not serialized at
failure; its guard/version and independent post-stop digest remain preserved.

Both exact executed guards, original two-command journal and resumed journal are
in the bounded text archive. Self-built reproducible binaries were removed only
after hash/log capture to preserve300MiB reserve. Source, raw channels, `.d`,
inputs, expected bytes and receipts remain. No captured ELF was copied/executed.

Two pre-source errors are preserved, not retroactively repaired:

- `CONTROL-ERRATUM.json`: the frozen MOV R12,R15 overlay selects address1, not
  scratch, because R15 is the minimum count. It was decoded inertly, never
  executed or counted as a source/value control. All12 native controls are finite
  operand distinctions, not executed array counterexamples.
- `RUST-PLAN-ERRATUM.json`: the original signed-merge witness never compared
  across signs. V2 uses the already frozen MAX-tail case. Original plan/arrays/
  expected wire remain unchanged; the corrected witness was frozen before Rust.

An earlier preparation-only unique-anchor check also stopped before compiler
invocation; the full block anchor was corrected without changing Rust/vectors.
Frozen proof/plan statements that source did not yet exist or source controls
had not run describe that earlier review point; later receipts document the
implementation separately.

## Reproduction, integration history and limits

The packaged portable verifier was adapted **after** execution for integrated
source origin/paths and archive wire loading. It did not produce the historical
phased receipt. Separate integrated read-only preparation invokes no compiler and
reproduces identical18-file compiler bytes. Reproduce a fresh qualification with:

```sh
python3 research/work-items/RE-006-n21-r20-tail1-rust-94/verify_native.py --out work/r20-native.json
python3 research/work-items/RE-006-n21-r20-tail1-rust-94/verify_rust.py --out work/r20-rust --compile --rustc /path/to/rustc-1.94.1
python3 -m unittest discover -s tests -p test_n21_run20_tail1_rust94.py
```

`checks.json` records exact current focused/static/manifest results. The prior
outer-admission manifest's lib and root-test paths move to byte-identical
archived copies with original SHA236c8e60…e226d and9652d0e1…3ecf1. Its source/
42-test receipt and raw archive stay historical and unchanged. Adding the export
initially made two old Python assertions compare the old library snapshot to
the new live library. The preserved failure led to a bounded current-test
resolver: read the historical pin, require the current outer export, allow only
the exact reviewed additive r20 export, and reject any other current-lib drift.
The original test bytes remain archived; current repaired-test results are
separate. No Rust or frozen comparison was changed or rerun for this repair.
Prior j8/j9/fixed21 history remains valid. The
whole PR retains two inherited archival EOF warnings (fixed21 j9 README:135,
j9 first-j8 README:126), reported separately from this scoped diff.

No import/submodule pin, dependency/root workspace, generated progress or gate
changes. Other run lengths, actual outer allocation reachability, libc identity,
original pointer/ABI/fault/unwind behavior, physical stores, runtime/byte equality
and full component gates remain open. Full repository suite remains pending.

Attribution follows explicit delegation OpenAI `gpt-6.1-sol`/`xhigh`, user UI
GPT-6.1 Sol Extra High, Codex cloud/CLI0.163.0; no machine-metadata read is claimed.
Contribution template a7e6b0fab2f767e14dbbd77021d98351e9470ba5, registry4;
ordinary self-reported contribution, no signed receipt or OAuth attempt.
