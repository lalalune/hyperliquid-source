# RE-006: j9 insertion and conditional first-front Rust

This reconstructs two **separate point relations** below the short-run path
left open by #1455 and after the local j8 step recovered by #1524. It does not
compose them into a sorting pipeline or assume the intervening seed/right
transformations. The earlier j8 implementation and compiled receipt remain unchanged; its two
shared-file snapshot pins are preserved in archived copies described below.

- Component: existing dependency-free `src/node94-orderbook`; manifest/lock
  unchanged, no crate/dependency/workspace or book-caller migration.
- Authorship base: main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Integrated on #1524 head `4cbaf4da30051d78ee05eb2bfad641463a7f4f11`,
  retaining both the historical j8 and new j9/front modules.
- Target: node94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Reference pin: can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  no inferred reference implementation was read or copied.
- Coordinates are linked ELF VAs, half-open. New code/docs are MIT; imported
  captures retain their rights. All component gates stay false.

## Qualified native relations

| Relation | Entry/premise | Reconstructed value effect |
| --- | --- | --- |
| Local j9 insertion | n21..32, arrival after ordinary seed returns and j8; RSI9/RAX72 at `4918f12` | Insert loaded A[9] into an arbitrary nine-word scratch prefix by shifting only its contiguous unsigned-greater suffix; equality stops |
| Conditional first merge-front | n21 merge-front state at `4918fe0`; current left/right fronts S[0]/S[10] | First qword at A[0] becomes unsigned min of those two current fronts; equality selects left |

The j9 claim ends at its first completion join `4918f06`. It reads only
within S[0..9), writes only within S[0..10), and can shift all nine words.
It does not require a sorted prefix or recover seed output. Only n21 exits
left immediately after j9: its next index10 equals h10. Other admitted counts
continue left at j10 and remain partial.

For n21, right-entry coordinates are S+80/A+80, seeded index8, length11;
control indices8/9/10 read A[18]/A[19]/A[20]. Under valid memory, ordinary
entry and the bounded scan argument, they reach merge setup. Complete right
array values remain unclaimed. Before the first merge load: right-front S+80,
left-front S, right-back S+160, left-back S+72, output-front0/back20.

The first-front corridor `4918fe0..4919018` is 56 bytes / 16 instructions.
It also reads S[20]/S[9] for back preparation, which does not alter the chosen
R10 front word before the first qword store. It establishes a **front-pair**
minimum, not a global minimum. A retained case selects8 while another scratch
word is0; sorted halves or an equivalent head-minimum invariant are unknown.

Memory must be valid, stable, nonwrapping and disjoint between source/output
A, scratch S and the callee's live spills/return machinery. Ancestor-frame
scratch is permitted. No raw pointer, overlap, lifetime, fault or concurrent
state acceptance is recovered. The Rust fixed initialized arrays and scalar
arguments are chosen safe value projections, not the native ABI/layout.
Returned index/side are chosen observations, not native RAX or original enums.
Physical compiler store count/order and later register effects are unclaimed.

## Pre-source wire freeze and independent comparator

`PRE-SOURCE-WIRE-FREEZE.json` was written while candidate source was absent,
SHA-256 `122af21ab3e379a398fa5c87b33ea0867d5041928834992bd31ef15e20bc6357`.
It preserves five previously frozen j9 states, four conditional front cases
(including the missing-global-minimum case), and one extra high-word front
boundary. It pins complete input/expected bytes before Rust source: 1,932
bytes each, expected SHA-256
`ea83daa6f6fb8b5e91a8a0d176c7ff749f65c41c832ad58a484c51e82d63153a`.
This is a local sequence record, not external timestamp attestation.

Records are tagged: kind0 calls only the fixed ten-word j9 helper; kind1 calls
only the conditional first-front writer. The input contains opaque IDs, the
operation tag, loaded value, old A[0] and 21 scratch words. It contains no
expected index, side or output. The driver emits all 21 scratch words, A[0]
and chosen observations; the external comparator checks every byte/field.
For j9 the extra 11 words are unchanged-footprint guards; front cases require
all scratch words unchanged. No case executes a j9-to-merge pipeline.

Builds use one fixed component/driver snapshot, including all compiler-read
Rust files and package pins. Mutants derive from that snapshot. Source/live
integrity and compiler/harness hashes are checked before success. Input and
expected artifacts are hash-checked before each client and at final report;
the same verified input bytes are sent to the client. The oracle loads frozen
wire bytes and literal expectations, not a second insertion/minimum algorithm.

The earlier standalone staging check required removing one extra blank EOF line from the
Python snapshot guard. `WHITESPACE-REBIND.json` preserves the executed/current
helper hashes, identical Python AST, unchanged 12-file component/driver
snapshot, frozen bytes and all 110 retained command-stream hashes. The 17
client streams were compared again and six focused controls rerun. The
original 55 compiled commands and their raw report were not restarted or
rewritten; Rust code and driver bytes were unchanged. That earlier result is
preserved byte for byte in `STANDALONE-COMPILED-RESULTS.json`. The fresh
combined-source run uses the corrected guard for all 55 commands and a
13-file snapshot (ten Rust files, two package pins and the component README).

## Historical j8 source pins

The predecessor j8 `compiled-results.json`, source module, driver, frozen
states, failed-plan receipt and controls are unchanged. Adding another module
changes the shared `lib.rs` and component README. Exact original copies from
head `4cbaf4da30051d78ee05eb2bfad641463a7f4f11` are retained in
`predecessor/first-j8/`. Only those two predecessor manifest paths are redirected
to these copies, keeping original SHA-256 values; its README self-hash is
updated for the explanation. The original j8 compiled receipt describes the
original head. The new combined build independently tests both modules; it
does not retroactively change the old result.

The copied intake records `J9-CLOSURE.md`, `J9-TRANSITION-FREEZE.json`,
`J9-STATIC-VALIDATION.json` and `N21-MERGE-FRONT-PREMISES.json` describe the
earlier pre-Rust stage and remain byte-for-byte unchanged. Their statements
about absent source/publication refer to that stage; this README records the
current compiled result and its separate source composition.

## Observed compiled checks

Official Rust 1.94.1 (`e408947bf`, LLVM 21.1.8), executable SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`,
built the real component at opt0/opt3 twice each, edition 2024 and overflow
checks enabled. All four ten-record runs match: 20 j9 and 20 conditional-front
record comparisons, zero value/index/side mismatches. These expectations come
from static native evidence, not target execution.

| Compiled wrong variant | Value mismatches | Equal-value observation mismatches |
| --- | ---: | ---: |
| j9 signed comparisons |1|0|
| j9 skip first predecessor |3|2|
| j9 wrong shift value |3|0|
| j9 omit final insertion |3|0|
| j9 omit initial append |2|0|
| j9 stop before front |1|0|
| j9 truncate loaded value |1|0|
| j9 shift equal predecessors |1|2|
| front signed comparison |1|0|
| front choose greater |4|0|
| front omit output store |5|0|
| front truncate output word |1|0|
| front equality chooses right |0|1|

Twelve controls have actual scratch/output-word counterexamples in their
respective native domains. The thirteenth changes only the chosen side
observation on equality and is never counted as a native value kill. The j9
equality variant has a real unsorted-prefix value counterexample; its other
two differences are separately labeled observations.

All 55 harness commands exit 0 with empty stderr; production builds deny
warnings. Thirty-three unique component tests pass at both direct optimization
levels and in both official Cargo `--offline --locked` debug/release profiles,
with zero doc-tests. Client bytes repeat within each optimization; all four
output streams agree. Raw rlib archive hashes differ without normalization.
`compiled-results.json` retains source/fixture identities, exact counts,
counterexamples and raw local log identities. Toolchain download verification
is attributed to the preserved parent installation receipt, not repeated here.

## Native replay and limits

The packet-local native validator rebinds four complete FDE/body/CIE records,
helper/relocation edges, and the combined 280-byte/75-instruction envelope.
GNU/LLVM agree on every partition/byte. Six previously frozen loop/coordinate
mutations are decoded as inert mode 0600 files and rejected below identity/window
guards. Normal and optimized Python replay produce identical exports/records.
These are finite decoder/property distinctions, not target runtime or a full
x86 equivalence proof.

`J9-RAW-STREAMS.json` contains hashes/metadata for raw static-mutant decoder
streams retained locally in the earlier intake worktree. Those raw files do
not accompany this packet; its paths are relative to that earlier worktree.
Current raw compiler/client/Cargo logs also remain ignored, with identities
in the receipts. Neither kind is claimed as a committed raw-log archive. Fresh combined logs
are retained locally under `work/re006-j9-integration`, with all 55 command
stdout/stderr identities in `compiled-results.json`.

```sh
python3 -B research/work-items/RE-006-j9-first-front-rust-94/verify_rust.py \
  --rustc /path/to/approved/rustc-1.94.1 --out work/j9-front-rust
python3 -B research/work-items/RE-006-j9-first-front-rust-94/verify_native.py \
  --llvm /path/to/llvm-objdump --out work/j9-front-native
python3 -O -B research/work-items/RE-006-j9-first-front-rust-94/verify_native.py \
  --llvm /path/to/llvm-objdump --out work/j9-front-native-O
python3 -B -m unittest discover -s tests -p test_j9_first_front_rust94.py -v
```

Use fresh output directories. `checks.json` records repository gates and the
fresh LFS-reference cache-status failure/recovery without changing input bytes
or persistent settings. The full repository suite remains coordinated and is
not claimed here; neither hosted CI nor clippy/rustfmt is claimed. No captured
node, emulator, network service, original ABI, seed/right transform, whole
merge/sort, byte-window credit or full-component gate is established.

## Preserved archival whitespace warning

The whole follow-on `git diff 4cbaf4da --check` exits 2 solely for
`predecessor/first-j8/README.md:126: new blank line at EOF.` The original
j8 README ends with that blank line; its byte-for-byte archive and original
SHA-256 `fe12475bfdb259763b0364b6082f0d25d9d9b07ea1a6752cf958076234ad697a`
are preserved. The warning is recorded rather than hidden with attributes or
rewriting the old bytes. The current component source and focused-test diff
passes the check. Whole-commit whitespace cleanliness is not claimed.

## Historical combined-source boundary

The compiled receipt in this packet describes the j8+j9 source closure at
`49877d8280fa82f164c9203507d510f6a928aed3`. A later fixed-n21 follow-on adds
modules to the same crate. Exact old shared `lib.rs` and component README bytes
are archived under `../RE-006-fixed-n21-delegate-rust-94/predecessor/j9-first-front/`;
only those two manifest paths move, retaining their original hashes. The old
j8/j9 modules, drivers, frozen cases and compiled receipts remain unchanged.
This packet’s33-test results are historical; fresh full combined-source checks
are recorded separately by the fixed-n21 packet.
