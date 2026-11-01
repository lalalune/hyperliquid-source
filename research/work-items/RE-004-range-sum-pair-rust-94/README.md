# RE-004: complete range-sum pair and shared helper in Rust

Node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
This supplies the Rust reconstruction missing from historical static PRs
#1346/#1349. It leaves catalogue, imported material and progress gates unchanged.

The complete 216-byte / 65-instruction closure comprises 0x514bc60 (99 bytes),
0x514bcd0 (104 bytes), and their full 13-byte helper 0x5032f40. Both follow the
same chain/bounds and 16-byte entry sequence. The first sums helper results;
the second discards each helper result and sums a different slot field. The
discarded helper still requires its reached input bytes. All reads finish
before the sole output store; arbitrary output/read aliases are supported.
Full RAX/RDX/RDI/RSI and every image byte are compared. PROOF.md derives all
reached widths, wrapped fields/cursors, empty/unreachable endpoints and the
last helper argument left in RDI. A proved mapped-byte bound rejects impossible
traversals without imposing an iteration budget.

All selected FDEs/CIEs and seven external caller FDEs (34,481 bytes / 6,818
instructions) are bound. Ten helper E8 sites are verified at decoded boundaries,
including the two selected calls. Neither outer entry has a direct E8/E9
candidate. All 80,300 RELAs contain no entry naming or selected-code writer.
GNU, LLVM and Capstone agree; 86 structural controls are effective. No unresolved
callee or static dependency remains, and no complete indirect xref census is
claimed. Helper-following code is excluded from its actual 13-byte FDE.

## Independent expectations and native qualification

The pre-Rust immutable-map / whole-sum oracle froze 8,316 cases: 3,424/3,413
admitted results and 734/745 refusals for the two members. Admitted cases include
702/710 empty ranges, 1,436/1,476 output aliases and 13/12 wrapped terminal cursors.
The independent peer counted 131 missing-discarded-helper refusals and 58 empty
unmapped endpoints. Synthetic numeric addresses never become host pointers.

All four input-only builds match all 33,264 outputs, including 27,348 admitted
results and 5,916 unchanged-image refusals. Optimization0/3 repeat artifacts have
identical hashes; three units pass per optimization. All 32 compiled mutants are
effective: 18 change admitted successful values and 14 affect admission only.
They cover the sum source, discarded helper read, double dereference, stride,
endpoint wrap/residue, register width, output byte width and late-store ordering.
The client consumes only inputs. Source and frozen oracle/fixtures were unchanged
during qualification. All 32 mutation spellings passed metadata preflight first;
there were no native or static qualification failures.

The lossless 46,418,654-byte archive retains 238 exact streams / 119 commands.
verify_recorded.py independently checks payload hashes, compiler-source pins,
full-image observations and effective mutation categories. A second reviewer
read the complete source/proof, independently walked snapshot intervals with
incremental sums and the second member's explicit reload, and rederived every
output. Manual ELF checks and fresh GNU bytes agreed. Parent replay reproduced
the exact computed report. An initial parent invocation omitted required
--objdump and exited2 before computation; its correction is documented in the
peer record. No expectation or qualified source was changed.

Doctor, verify, catalogue-check, reproduce, 50 focused predecessor/FDE/GNU tests
and rustfmt pass. The shared baseline attempted 971 files / 15,462 tests / 69
skips. Its original exit2 had three disk-full errors; all 20 affected tests passed
isolated retry. shared-baseline-result.json retains that outcome and log hashes.
No successful full-sweep repeat, per-head full suite, skipped Linux run or hosted
CI success is claimed.

## Reproduction and limits

```sh
python3 -O -B research/work-items/RE-004-range-sum-pair-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-range-sum-pair-rust-94/verify_recorded.py
python3 -O -B research/work-items/RE-004-range-sum-pair-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/range-sum-pair-replay
```

Use a new output directory. The compiler path may differ; its exact identity is
checked: rustc1.94.1, commit e408947bfd200af42db322daf0fadfe7e26d3bd1,
SHA-256 b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6.
The documented independent no_std crate builds directly with rustc; this does
not invent a root Cargo workspace or claim an original build. Profiles bind
edition2024, aarch64-apple-darwin, denied warnings, overflow checks, one codegen
unit and system linker. Static tools are GNU2.47.20260726, AppleLLVM17 and
Capstone5.0.7. Exact commands, stream hashes and versions are retained.

None is new unchanged-image refusal. Original successful correspondence assumes
stable ordinary memory and disjoint valid stack/control storage. Original ABI,
fault ordering, MMIO, races, control-stack aliases, captured execution, instruction
emulation, compiled-byte identity and whole-node equivalence remain outside this
projection. Names describe observed relations, not recovered source identities.

Final live inventory:209 open PRs, zero open issues and100 recent merges.
The only matches are historical static #1346/#1349 and adjacent string-concat
#1343, which ends at the first selected entry and is excluded. No existing
Rust implementation or open claim overlaps this closure. Inventory retained
in final-overlap.json.gz.
