# RE-008: second QC group's first short-input failure

Native expectations were frozen before the Rust extension below. This packet
is uncommitted and unpublished. Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All coordinates are linked ELF virtual addresses; ends are exclusive. Source
base is draft #1509 head `35d44f7130bc029b30723e7464ac7d8ff3644a40`.

## Qualified question and frozen relation

At the second QC-group call `0x4c7e422`, what happens when the first incomplete
integer is at position k in 1..4? D has mode dword 1 and entry charge C/limit L
with C<=MAX-32 and C+32<=L. Its input begins with k-1 complete FD+eight-byte
payloads, followed by either FD with m available payload bytes, m in 0..7, or
physical EOF before the next marker. Memory/state/output/active stack frames
are valid, nonwrapping, stable and disjoint; ordinary call preservation and
normal returns are premises. Earlier row consumers and mode construction are
not reconstructed. These are conditional helper-entry states, without a claim
that every fixture is reachable after the preceding QC consumers.

| First incomplete scalar | Pointer advance | Remaining suffix | Active kind/need |
| --- | ---: | --- | --- |
| FD plus m payload bytes | 9(k-1)+1 | exactly those m unread payload bytes | byte 0 / qword(8-m) |
| EOF before marker | 9(k-1) | empty | byte 0 / qword 1 |

Both cases retain charge C+32. Exactly k scalar wrappers are attempted; no
later group scalar is called. Group output has tag qword 1 at G+0, kind byte 0
at G+8, need qword at G+0x10. The second-group row error corridor forwards
the same fields at row-output+0/+8/+0x10 and returns before recovery entry
`0x4c7e4f3`.

**A kind byte 0 does not make the whole qword at +8 zero.** The other bytes in
that word and the copied inactive error payload are unconstrained. This packet
does not freeze or compare a full 40-byte error image, infer initialized padding,
or recover a source error enum/ABI.

## Exact native chain

Four complete FDE bodies are authenticated in `PRE-RUST-FREEZE.json`:

| Body | FDE | Size | SHA-256 |
| --- | --- | ---: | --- |
|`0x466bf60..0x466c13f`|`0xef1f28`|479|`aa484554c9abb65bea26e5450e6cda287fc037cc7c53a47ed5e04e2069ab44a0`|
|`0x466bd10..0x466bdf5`|`0xef1eac`|229|`fca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e`|
|`0x466d980..0x466dabc`|`0xef2378`|316|`1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b`|
|`0x4c7e340..0x4c7e60d`|`0xf443ac`|717|`691aada3f78a0a84acaa2b4e75ce3c58fe68b1e852aa29a98e464287e1ebf512`|

All four use CIE `0xce1518`, have no LSDA and uniquely match the unwind index.
Existing complete group/wrapper GNU/LLVM exports in the success packet are
dependency-hashed and independently checked against this capture, avoiding
duplicate copies. New exports retain the complete Reader and 217-byte row call/
error corridor: 95/53 instruction rows with identical GNU/LLVM byte partitions.
Complete body authentication is not a whole-body semantic recovery claim.

1. The established group reserve/adjustment and scalar charge sequence makes
   every attempted primitive charge C+32. The prefix successes take the fast FD
   arm: even the final complete scalar before a failure has at least 9 bytes.
   Each earlier success causes the observed 8-unit refund before the next 8-unit
   scalar charge. Failure does not trigger a post-call refund or rollback.
2. At the failing call N is 0..8. Wrapper `0x466bd41` selects its slow arm,
   passing D+0x10 with EDX=0 through slot `0x57745e0`. The unique RELATIVE
   relocation is type 8/symbol 0/addend `0x466d980`; raw slot/RELA bytes are frozen.
3. Reader N=0 branches at `0x466d988` to byte kind 0 and qword need 1 stores at
   `0x466d9b5/b8`, with no cursor store. Otherwise `0x466d999/99c` first store
   P+1/N-1. FD selects table index 2 at `0x6f6ed8`, reaching `0x466d9f4`.
   N<9 chooses ECX=9 and `0x466da0c..12` stores byte kind 0, qword need 9-N.
   No partial payload is loaded or consumed. Reader/error-builder/allocator
   paths for other markers are not selected.
4. Four exact failure edges stop the group success corridor:

   | Position | Call | Tag 12 check / JNE | Error join | Need source |
   | --- | --- | --- | --- | --- |
   |1|`0x466bfbe`|`0x466bfd5/d7`|`0x466c0ac`|R15|
   |2|`0x466c001`|`0x466c018/01a`|`0x466c0b3`|R13|
   |3|`0x466c044`|`0x466c05b/05d`|`0x466c0bd`|RBP|
   |4|`0x466c083`|`0x466c09a/09c`|`0x466c0c7`|RCX|

   Each special-tag 13 check is false for kind 0. Joins 2/3/4 move the selected
   need into R15 at `0x466c0b8/0c2/0cc`. `0x466c0f6` moves R15 to R13 and
   `0x466c10a` writes it as a qword to G+0x10. Common construction sets EDI=1
   at `0x466c0e9`, writes the tag qword at `0x466c0f9` and preserves AL as
   only the low kind byte at `0x466c100..106`. No selected error join contains
   a call, decoder-state store or edge back to a later scalar. Return is
   `0x466c124`.
5. At the row, G is row-RSP+0x28. `0x4c7e427` reads kind byte at G+8;
   `0x4c7e43c` reads need qword at G+0x10. Tag 1 makes JE `0x4c7e450` false.
   `0x4c7e460/463` save need/kind in R15/EBP before common join `0x4c7e465`.
   `0x4c7e47d/480` restore RDX/ESI, and `0x4c7e4b8/4ca` store kind byte/
   need qword. `0x4c7e4da/4df` write row tag qword 1, returning `0x4c7e4f2`.
   The complete error corridor has no call or decoder-state write. The
   recovery-byte entry is beyond the return and cannot be reached on this path.

## Freeze and controls

`inputs.tsv` contains only ids and actual charge/limit/wire inputs. Separate
`expected.tsv` freezes all 32 k/m combinations plus 4 EOF cases. The payload
canaries and prior complete values are asymmetric. Charges include 0, 7, 255 and
MAX-32; budgets include exact equality and headroom. Expected pointer advance,
remaining length, exact suffix, retained charge, group tag/kind/need and row
tag/kind/need were fixed before a new Rust implementation or projection model.

Ten frozen opcode edits provide concrete static counterexamples: the four stop
branches, FD shortfall, marker step, group need slot, row need slot, one refund
and row error-route selection. They are not executed patched binaries. The
fourth-stop and row-route edits invalidate the baseline group/route guarantee;
later outcomes are deliberately unclaimed. The marker-step control can produce
an inconsistent native pointer/remaining pair and is native-only, not evidence
that a borrowed Rust slice can represent that state. Need-slot controls state
their initialized-zero destination premise; no inactive bytes get a meaning.

## Independently compiled Rust extension

The existing consensus component now has an error-aware FD-only outcome API in
`src/qc_fd_group.rs`. Its chosen `FdGroupOutcome` enum has no native layout/ABI
claim. For admitted FD inputs it returns complete values or the first incomplete
need, updating only final charge and input suffix. Nonadmitted/other-marker
inputs return `OutsideDomain` unchanged, a chosen safe-API behavior. It does not
reconstruct native reservation failures. The original bool function's 1,016 bytes
remain byte-identical (SHA-256
`6550a8bfdfca51027a202188ecb459e1c7bee638cf09e1d482e03fa382e2e3c7`).

`observed_short_fields` exposes the defined group tag qword, kind byte and need
qword. Row forwarding is rendered by the separate input-only example; this is
not a library implementation of the row decoder or its error ABI. The program
reads only id/charge/limit/wire on stdin. It has no expected-file access.

Before this source existed, `RUST-PROTOCOL-FREEZE.json` fixed 44 comparison rows:
the 36 new errors plus 8 already-frozen successful FD groups from #1509. The new
protocol expresses active fields, pointer advance, remaining length, exact
suffix and successful 32-byte values; no inactive error image enters it. The
old 36-row native freeze and both original success fixtures remain unchanged.

Pinned Rust 1.94.1 builds/runs the real component in opt0/opt3. Baseline matches
44/44 in each profile. Nine source mutants compile/run and disagree on
8,8,8,8,32,28,44,36,36 rows per profile: four failure-position stops, shortfall,
partial-payload consumption, retained charge, group need and driver row need.
All cases are in the original native domain; no semantic mutant is killed only
by compilation or an outside-domain guard. Static native controls and compiled
source controls have separate counts and scopes. The stop variants have their
concrete native-site witnesses at FD/m0; their behavior on every other corrupted
path is not claimed equivalent to patched native code. Marker-step inconsistency
and row-route bypass remain native-only controls. Missing-need source controls
use the frozen initialized-zero native destination counterexamples.

`RESULTS.json` pins actual source/fixture/tool/stream/executable receipts. Cargo
dep-info is checked against every compiler-recorded project input: exactly 13
Rust sources, the 12 crate modules plus this selected example, with 15 source/
manifest/lock pins. Other examples and expected data are outside that compilation.
The component manifest/lock/dependencies are unchanged. Original #1509 packet
bytes/source pins remain historical; the new source pins describe the extension.

Focused Python passes 12/12 (three new snapshot/active-state/control tests).
Cargo all-targets passes 51 tests per profile and builds all four examples.
`make doctor`, `make verify`, `make catalogue-check`, `make reproduce` exit 0 on
the materialized local tree. Exact pinned reference contents were copied from
already authenticated local stores with lazy fetch disabled; standard LFS
filters were command-local and only verified index stat metadata was refreshed.
No input/pin/configuration/catalogue edit was made. Full repository `make test`
is deferred to coordinator integration; no additional full suite was requested.

To reproduce from the repository root:

```sh
python3 research/work-items/RE-008-qc-fd-group-short-94/verify.py \
  --target artifacts/node/94/hl-node --llvm /path/to/llvm-objdump \
  --out work/qc-fd-group-short/new-native.json
python3 research/work-items/RE-008-qc-fd-group-short-94/verify_rust.py \
  --rustc /path/to/rust-1.94.1/bin/rustc \
  --out work/qc-fd-group-short/new-comparison
python3 -m unittest tests.test_qc_fd_group_short94 -v
```

Use a new comparison output directory. Raw local receipts/snapshots are retained
under ignored `work/qc-fd-group-short/`. Native exports are regenerated twice;
byte overlays are analyzed below identity checks without producing/executing
patched captures. Passing finite cases corroborates the static branch argument;
it is not target-runtime or original-machine-code equivalence.

## Ownership and limits

Fresh scan: 212 open PRs, three pages; only #1509 names the selected group/call.
#1365 head `4d33431de9eb9c5c9c8d145d1e61b75a9634d57f` owns the scalar
wrapper/Reader results credited above. #1366 head
`198ff2d031763ccf2e075ca91762abba70340a94` owns outer consensus construction
at `0x4752890`; its proof/contract contain none of the selected addresses.
The earlier private first-call FB/EOF groundwork is credited and is not being
republished as a separate static result. #1509's successful FD group, byte
field and assembly remain unchanged.

Independent native/freeze review preceded Rust. Final source/receipt review is
pending; no integration/publication is authorized by these local checks. Active
logical fields/state only are qualified; all original ABI/lifetime, full-row
reachability, other-marker/mode, reservation-error, unwind and cryptographic gaps
remain. No captured executable is run/emulated and no full gate advances.
