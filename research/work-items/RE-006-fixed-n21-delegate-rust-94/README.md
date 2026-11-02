# RE-006: fixed-n21 original-input delegate values in Rust

This closes the seed and continuation gaps left by #1455 and #1524 for one
fixed-count normal-value route. It independently reconstructs the node94
delegate's **n=21** input/output relation in the existing dependency-free
`src/node94-orderbook` component. Book callers are unchanged.

- Target node94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  91,774,280 bytes. Coordinates are linked ELF VAs, half-open.
- Integration predecessor: #1524 head
  `49877d8280fa82f164c9203507d510f6a928aed3`, based on main
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- can1357 reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No inferred unlicensed implementation was read or copied. New code/docs are
  MIT; imported inputs retain their rights. No component gate is advanced.

## Exact claim and premises

For A at **entry of delegate `4918d30`**, count21 and scratchcap>=37, the
qualified native route returns with A[0..21) sorted as unsigned qwords.
Scratch contains the following complete value image:

| Scratch words | Final values from delegate-entry A |
| --- | --- |
| S[0..10) | sort(A[0..10)) |
| S[10..21) | sort(A[10..21)) |
| S[21..25), S[25..29) | sort(A[0..4)), sort(A[4..8)) |
| S[29..33), S[33..37) | sort(A[10..14)), sort(A[14..18)) |

A21 and S37 must be valid, stable, nonwrapping and disjoint from one another
and the selected caller/producer live PUSH/CALL/saved/return storage. Relative
to caller-entry SP=C, that excluded range is [C-120,C+8). Disjoint ancestor-frame
scratch is permitted. Pointer formation includes a temporary S-8 back boundary,
which is never dereferenced. Aliases, concurrency/MMIO, faults and exceptions
are excluded. Rust fixed arrays and returned snapshots are chosen safe value
projections, not the native pointer ABI, allocation layout or return object.

This does not establish outer-core/collector reachability for every supplied
array, generic counts, original source/build identity, failure/unwind behavior,
or a full orderbook/node gate. "Original A" never means an earlier outer-core
array before any possible transformation.

## Native proof and consequential details

The complete producer `4912a50..4912d13` is 707 bytes/196 instructions, FDE
`f17fcc`, CIE `ce1518`, no LSDA. The selected complete delegate is
`4918d30..49190b7`,903 bytes/254 instructions, FDE `12a6ee4`, CIE `fbdc2c`,
LSDA `b8638c`. Full core/adapter context is also digest/FDE-bound; complete
body authentication is not an all-count semantic or compiled-byte claim.

1. Each producer orders two four-word groups into auxiliary8. Four strict
   unsigned p/q partitions prove its middle candidates and exact permutation.
   Four two-ended pairs then write destination order0,7,1,6,2,5,3,4.
2. The fourth right-front boolean uses SETB BPL with stale upper RBP bits.
   EBX was cleared first; later MOV BL,BPL creates the full bounded0/1 cursor.
   Back equality stores a left-loaded equal value while retiring right.
3. The n21 calls seed A[0..8)->S[0..8),auxS[21..29), then
   A[10..18)->S[10..18),auxS[29..37). The source A remains unchanged.
4. Existing qualified left j8/j9 insert A[8],A[9], establishing sorted left10
   and rightseed8 from actual producer effects. New right j8/j9/j10 insert
   A[18],A[19],A[20].
5. The324-byte/92-instruction continuation uses ten front/back pairs and one
   center. There is no exhaustion branch: a stable-rank/crossed-cache proof
   closes both early-exhaustion shapes and both final cursor guards. Native A
   store order is0,20,1,19,...,9,11,10, all qwords.

`seed/SEED-COMPOSITION-PROOF.md` and `prepared/N21-CONTIGUOUS-PROOF.md` contain
the complete arguments and limitations. Both received independent read-only
review. Thirty-seven frozen same-width operand/caller controls are finite
decoder distinctions, **not executed target array counterexamples**. Normal
and optimized Python native qualification pass. Raw tempfile filename headers
differ between runs; no whole-report raw-byte equality is claimed.

The failure dispatcher and seed-unwind memcpy path are bound but not interpreted
transitively. All admitted normal-path helper and register-restoration premises
are stated; error, hardware and ABI behavior remain unknown.

## Pre-source expectations and the two compiled denominators

`seed/SEED-PRE-SOURCE-FREEZE.json` SHA-256
`01d890d7b29a54f756955b5767bc7db1bf96a753c4908052f42d0e76e44e6e7b`
was frozen before new seed Rust. It includes80 delegate-entry A21 cases,
asymmetric initial scratch markers,24 distinct quartet permutations and81
three-value duplicate quartets. All four p/q partitions occur. The oracle uses
immutable integer sorting and bisect splices, independently of Rust.

The original-input client consumes only IDs, A21 and initial S37. Its four
build/repeat outputs exactly match80 records each: **320 original-input record
comparisons**, each with 153 qwords and one chosen Rust Result status:

- 21 unchanged source words after seeding;
- 37 post-seed scratch words;
- 37 scratch words after the two left insertions;
- 21 final output words and37 final scratch words.

The pre-source plan adds status0/1/2 for the new safe API's continuation Result;
it is not native RAX or a native failure enum. All production statuses are0.
The status refinement preserves every frozen qword; input SHA is
`18822cd0f05221491c636cb12c80ad92d93c3c96ed4a7b4c29a4ad4dcefbd7a4`,
refined expected SHA is
`9ccfa25e6e18b21623f6e59fc75dc066a1bda997c940ed885677527534d6106d`.
`seed/PLAN-ANCHOR-ERRATUM.json` corrects three anchor spellings while preserving
the original frozen17-control plan, arrays and semantic predictions.

**The five insertion indices and58..107 full-route logical writes in this
freeze remain static expectations. The original-input driver does not compare
them. It does not measure physical compiler/native store order.**

The separate prepared-state driver retains its 80 admitted conditional cases
plus 4 safe API refusal cases: four 84-record runs match, giving320 conditional
and16 policy record comparisons. It compares A21/S37 and chosen right-insertion,
center/cursor/provenance/logical-write observations. Its S37 guards validate the
safe model/driver prefix projection, not physical native memory. The old80
arbitrary auxiliary states are not all shown reachable: the actual producer
fills S[21..37) with the quartet sorts above. These denominators stay separate.

Both clients are input-only; expected values never reach Rust. Fixed complete
component/driver snapshots, live/source checks and fixture identity checks bind
the comparisons. Each snapshot has14 component files plus its driver, including
all old/new modules, both package pins and component README. The union contains
two different drivers. Cargo dep-info confirms10 production/11 test Rust files.

## Observed compiled controls and preserved failures

Official Rust 1.94.1 (`e408947bf`, LLVM21.1.8), executable SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`,
was invoked by absolute path, edition2024, opt0/opt3 twice each, overflow checks
enabled. Production builds deny warnings. Toolchain provenance is attributed
to the preserved official-install receipt, not a fresh download.

The original-input qualification is explicitly phased:

- Attempt 1 failed on two must-use diagnostics before any client ran. The source
  now explicitly discards the existing j8/j9 chosen indices; frozen values did
  not change. Its failed source/snapshot/diagnostics are retained.
- Attempt 2 completed four original-input runs,39 tests at each direct profile
  and14 controls, then failed compiling the j8-skip control: removing the call
  removed type inference for a window and left an unused import.
- Production bytes stayed unchanged. Only two countermodels gained explicit
  window types and noncalling helper references. The resume rechecked all source
  and wire pins, reused 58 completed command streams, and actually executed the
  remaining 9 commands. Attempt 2 remains failed; no blanket rerun is claimed.

The final phased receipt distinguishes reconstructed old argv from actual
resumed commands, and retains both harness revisions. The original phase's
compiler checksum local was not serialized on failure; its startup check ran,
and the current executable matches the installed pinned hash. This limit is
explicit rather than retroactively inventing a stored value.

All 17 original-input controls have actual cutpoint/final array-value witnesses.
Some also change the safe API status; those counts are separate from values
and are not interpreted as target failure behavior. The additional prepared
qualification has 73 actual successful commands and19 controls:15 have array
witnesses; four change only chosen metadata/logical writes. `compiled-results.json`
selects first actual array witnesses separately from generic first mismatches.
For center-always-left and left-exclusive-plus-two, case0 is metadata-only;
the first array witness is case1.

Thirty-nine unique component tests pass at direct opt0/opt3 and Cargo debug/
release `--offline --locked`, with zero doc-tests. Repeated executions do not
multiply the unique test count. Exact source/fixture/stream hashes, diagnostics,
counterexamples and lossless raw outputs are in the durable receipts/archive.
No captured executable or instruction evaluator was run.

## History, whitespace and remaining checks

The j8/j9 source modules, drivers, frozen cases and compiled receipts are
unchanged. Exact shared component README/lib bytes from49877d82 are archived
under `predecessor/j9-first-front/`; only two old j9 manifest paths now point
there with their original hashes, and its README explains the historical
33-test source closure. The earlier first-j8 archives/pins remain untouched.
Fresh combined39-test results are separate from those historical receipts.

The whole follow-on whitespace check has one preserved exception:
`predecessor/j9-first-front/README.md:135: new blank line at EOF.` This exact
old byte image has SHAe3b3b27c...fc591be. It is not rewritten or masked with
attributes. Current source/driver/test changes pass the whitespace check;
whole-commit whitespace cleanliness is not claimed. Both old manifests pass.

The terminal `make doctor verify catalogue-check reproduce` exits0. Thirteen
new focused Python tests plus the seven j8 and six j9 controls pass (26 total).
No full suite rerun was performed. `checks.json` records these scoped results and
the invocation-local LFS cache refresh after authenticating exact local pins,
pointer and payload. No persistent config, imports or dependency pins change.
The full repository suite remains coordinated separately; hosted CI success,
clippy/rustfmt, compiled-byte identity and component gates are not claimed.

```sh
python3 -B research/work-items/RE-006-fixed-n21-delegate-rust-94/verify_rust.py \
  --rustc /path/to/rustc-1.94.1 --out work/fixed-n21-original
python3 -B research/work-items/RE-006-fixed-n21-delegate-rust-94/prepared/verify_rust.py \
  --rustc /path/to/rustc-1.94.1 --out work/fixed-n21-prepared
python3 -B research/work-items/RE-006-fixed-n21-delegate-rust-94/verify_native.py \
  --llvm /path/to/llvm-objdump --out work/fixed-n21-native
python3 -B -m unittest discover -s tests -p 'test_fixed_n21*94.py' -v
```

Use fresh output directories. `oracle-history/` preserves the original
pre-source generators; they are historical sequence evidence, not commands
that should overwrite frozen cases after implementation. Current comparators
serialize literal frozen fields, not the production algorithm. Next gaps are
other counts, outer-core/caller composition, aliases/ABI and failure/unwind paths.
