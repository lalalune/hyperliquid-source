# RE-006: conditional incoming route to the fixed-21 delegate

## Concrete gap and observed native result

This extends #1524's delegate-entry value reconstruction with one incoming
wrapper/core/adapter route. For 21 stable unsigned qwords whose first natural
run has length 2–10, node94 reaches `0x4918d30` with the original array unchanged,
count21, actual wrapper stack capacity512, and all64 opaque context bits.
The short-run branch occurs before descending reversal. A run of length11 is
the first excluded boundary; length1 is impossible for valid21-word input.
Excluded cases mean outside this first-short-run route, not native rejection
or absence of every later delegate call. No new whole-wrapper sorting result
is asserted.

Target: node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
(91,774,280 bytes). Coordinates are linked ELF VAs, half-open intervals.
The complete primary native bodies are wrapper `0x4486d10..0x4486e1d`
(269B/75 instructions), core `0x4dbd490..0x4dbdb5e` (1742/421), and adapter
`0x4497a90..0x4498022` (1426/362). FDE/CIE identities, continuous GNU/LLVM
partitions and selected E8/RELATIVE edges are bound in the intake/proof/receipts.
The core slot `0x57768a0` resolves to the adapter, which directly calls the
delegate. #1455 owns the earlier wrapper/monotone findings; #1430 owns the
collector edge. Those findings are credited, not counted again.

## Active premises and exact unresolved boundary

Let wrapper-entry RSP be W and stack scratch base S=W−0x1028. Require valid,
stable, nonwrapping A21 and ordinary nonfaulting call behavior; its168-byte span
must be disjoint from the selected live `[S−0x420,W+8)` chain. This includes
callee frames, saved registers, scratch and return machinery. Ancestor-frame
input above W+8 is permitted. Actual512 scratch qwords exceed the delegate's
required37, including auxiliary storage.

Disjointness is an external runtime premise. The collector's allocation slot
resolves to TLS allocator `0x54c06b0..0x54c0772`; its runtime ownership/freshness
and real call-state instantiation remain unresolved. Source preservation at
delegate entry is established by the native CFG's reads/frame-only stores under
this premise. Conditional ordinary return structurally makes no further A access
or second adapter call, but this packet adds no whole-sort outcome.

## Independent Rust and comparisons

`n21_outer_admission::first_short_run21` extends the existing dependency-free
orderbook component. Its immutable21-word safe value API computes the unsigned
natural-run predicate and returns a symbolic selected request or outside-route
observation. It performs no delegate effect, scratch allocation or sorting.
Addresses, original ABI and native return types are not invented. Run/direction
fields are chosen observations; excluded-case zero fields are client framing.

The76 literal cases (56 admitted/20 excluded), all20 adjacent-order facts,
high-bit/tie/r11 boundaries, six symbolic alias relations and ten source-control
predictions were frozen before Rust. The impossible r1 is a fact, not a fake
array. Six isolated flag-word controls distinguish the native BYTE test; actual
wrapper n21 normalizes its flag to1. Alias-negative examples are outside the
proof domain, not native refusal predictions.

The preserved proof/freeze statements that Rust did not yet exist describe
their pre-source review point. Subsequent compiled/preparation receipts below
record the later implementation; frozen originals are not silently rewritten.

Historical **attempt1** `compiled-results.json` records46 actual commands with
official Rust1.94.1, optimization0/3, overflow checks and warnings denied:

- Four×76 literal216-byte client records match exactly; each contains21 input
  words plus six chosen routing fields. The client echoes source words by
  construction. This validates client/projection framing, not physical native
  preservation or native target execution.
- All42 existing-component unit tests pass in each direct optimization profile.
- All10 preplanned mutants have their exact predicted field witness: seven
  admission controls and three count/capacity/context argument controls. These
  are source-projection counterexamples, not native-executed array kills.
- All92 raw stdout/stderr channels are retained; stderr is empty. There was no
  failed compiler attempt. No Cargo, full repository suite or hosted-CI success
  is claimed for this extension.

The run compiled a conservative17-file snapshot: the exact predecessor component
plus one module/export, driver and duplicate candidate source. This is not an
exhaustive rustc `.d` dependency or sysroot audit. Compiler digest/version and
the official installation receipt are recorded; installer downloads were later
removed by the parent after hash verification. No new toolchain was installed.

`RAW-COMPARISONS.json` retains the exact executed guard SHA6d8a8263…9b42,
all source snapshot bytes, ten changed mutant modules, wires and command streams.
The packaged portable `verify_rust.py` was adapted **after** that run for current
source origin/paths and explicit compiler selection. It did not produce the old
46-command receipt. Separate `integrated-preparation.json` is read-only
preparation, with no compiler invoked; its17-file compiler snapshot equals the
historical executed snapshot byte for byte. Historical source/control receipts
are not relabeled as a new current-tree compiler execution.

## Static controls, reproduction and preserved history

The pre-source16 same-width overlays distinguish native operands with GNU
objdump2.44 and LLVM19.1.7 `llvm-mc`, using tiny raw fragments only. The preserved
`STATIC-VALIDATION.json` is the first static receipt; its transient full fragment
headers were not retained. The portable static rerun separately retains all128
actual decoder stdout/stderr channels in the archive and reports complete
six-body/FDE and selected call bindings. These finite decoder/property distinctions
are neither target execution nor whole-sort proof. Full primary GNU/LLVM exports
normalize only the input filename header.

Run from the repository:

```sh
python3 research/work-items/RE-006-n21-outer-admission-rust-94/verify_native.py --out work/outer-native
python3 research/work-items/RE-006-n21-outer-admission-rust-94/verify_rust.py --out work/outer-rust --compile --rustc /path/to/rustc-1.94.1
python3 -m unittest discover -s tests -p test_n21_outer_admission94.py
```

`checks.json` records exact safe repository/focused/manifest outcomes and initial
missing-reference failures. Local references were materialized only from
authenticated terminal local Git stores; node94 LFS OID/size and donor/recipient
digests/modes matched. No remote fetch, hooks, setup or persistent settings ran.
An initial nested-alternates clone failure and a skip-smudge index-refresh failure
are preserved separately; invocation-local standard LFS filters resolved the
verification precondition. Imports/submodule pins remain unchanged.

Only the old fixed21 manifest's lib path is redirected to the byte-identical
`predecessor/fixed-n21/lib.rs`, SHA3f8d6265…dbd9. Its original compiled receipt,
archive, modules, driver and all other manifest entries remain unchanged.
Older j8/j9 manifests remain historical and valid. The whole-PR diff retains
two inherited archival EOF warnings: the fixed21 packet's
`predecessor/j9-first-front/README.md:135` and the j9 packet's
`predecessor/first-j8/README.md:126`. This extension introduces no archival
README copy. The new scoped diff is checked separately.

No captured executable or instruction evaluator ran. Generic counts, other
natural-run routes, allocator ownership, actual outer-collection reachability,
physical store traces, source/target runtime or machine-code equivalence,
exceptions, original ABI and full component gates remain open. No progress gate
or byte-coverage credit is changed. Full repository suite remains pending.

Attribution: independently authored by delegated OpenAI model `gpt-6.1-sol`,
effort `xhigh`, user-confirmed UI “GPT-6.1 Sol Extra High”, client Codex cloud /
Codex CLI0.163.0. This follows explicit delegation, not a machine-metadata read.
Contribution template revision `a7e6b0fab2f767e14dbbd77021d98351e9470ba5`,
project registry4; ordinary self-reported contribution, no signed run receipt.
