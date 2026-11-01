# RE-004: pointer snapshot, dword flag and conditional byte clear

Target node94:91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
This closes a bounded Rust gap in the historical foundation flag-set packet.
It does not advance a component gate or infer a source-level flag meaning.

The independent safe no_std library reconstructs complete leaf
`0x53cf560..0x53cf57e` (30 bytes/seven instructions). It snapshots the full
pointer at O+0x1a0, writes dword1 at O+0x108, then clears one byte through the
snapshot iff nonzero. The second store can erase the just-written flag or alter
the pointer's source bytes; full returned RAX still contains the entry snapshot.
Full preserved RDX and the entire image are observed. PROOF.md establishes all
raw pointer values, wrapped fields, exact byte widths, alias effects and the
safe unchanged-image refusal, distinct from original partial-fault behavior.

The unique complete FDE/CIE and seven complete caller FDEs (39,790 bytes/7,839
instructions) are bound. All seven E8 candidates are actual decoded calls.
All80,300 RELAs contain no entry naming or selected-code writer. No helper,
static-data or import dependency remains; indirect reachability is not complete.
GNU, LLVM and Capstone agree after three exact observed LLVM LOCK display joins
at0x51d344d,0x536a51a,0x537b600. The initial strict partition failure and original
checker are retained in initial-static-boundary-failure.json.gz. Only those
exact address/byte pairs are joined; raw listings remain unchanged. This
correction preceded both oracle freeze and Rust. All24 static controls pass.

## Independent expectations and native qualification

The immutable-byte-map / ordered-overlay oracle froze5,123 cases before Rust:
3,842 admitted results and1,281 refusals. Coverage includes31 null snapshots,
282 clears aliasing pointer-source bytes,89 clears aliasing flag bytes,
eight zero-object cases and1,254 wrapped-object-field cases. Every possible
fixture clear-byte position is exercised; all image bytes and full RAX/RDX are
compared. The input-only client never receives expected outputs.

All20,492 observations match four native builds, with identical repeat artifacts
at opt0/opt3 and three units per optimization. All25 compiled controls are
effective:16 change admitted successful values, eight change admission only,
and one changes79 refusal images by storing the flag before clear validation.
That last control tests only the new safe refusal contract. All25 mutation
spellings passed metadata compilation first; no native qualification failure
occurred. The source, pre-Rust oracle and frozen fixtures stayed unchanged.

The lossless11,772,192-byte archive retains196 exact streams/98 commands.
verify_recorded.py checks every payload hash, command outcome, source pin,
full-image result and effective mutation category. Archived duplicate outputs
were removed only after exact reconstruction equality; archives stay retained.

Doctor, verify, catalogue-check, reproduce,29 focused predecessor/FDE/GNU tests
and rustfmt pass. The separate shared baseline attempted971 files/15,462 tests/
69 skips. Original exit2 had three disk-full errors; all20 affected tests passed
isolated retry. shared-baseline-result.json retains that outcome and log hashes.
No successful full-sweep repeat, per-head full suite, skipped Linux execution or
hosted-CI success is claimed.

## Reproduction and limits

```sh
python3 -O -B research/work-items/RE-004-flag-set-clear-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-flag-set-clear-rust-94/verify_recorded.py
python3 -O -B research/work-items/RE-004-flag-set-clear-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/flag-set-clear-replay
```

Use a new output directory. The compiler path may differ; its exact identity is
checked:rustc1.94.1,e408947bfd200af42db322daf0fadfe7e26d3bd1,
SHA-256 b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6.
The no_std crate is built directly with rustc; no root Cargo workspace or original
build is invented. Profiles bind edition2024,aarch64-apple-darwin, denied warnings,
overflow checks, one codegen unit and system linker. Static tools are GNU2.47.20260726,
AppleLLVM17 and Capstone5.0.7. Exact commands, streams and identities are retained.

The correspondence assumes stable ordinary memory and valid disjoint control/
return storage. Native ABI, fault ordering, MMIO/races, control-stack aliases,
captured execution, instruction emulation, original compiled-byte identity and
whole-node equivalence are outside the projection. Pins, imported evidence,
catalogue and progress gates remain unchanged.

## Second review and submission inventory

A second reviewer independently checked all5,123 records with direct interval
reads and explicit snapshot/stores, fresh32 bytes (30-body+2padding), all eight
selected/caller FDEs, seven actual call edges and all RELAs. The parent replay
reproduced the exact report. No blocker was found. There is no fixture isolating
a missing flag span after a present pointer source; that case is covered by the
checked-span proof, not claimed as observed native coverage.

The final scan includes217 open PRs, zero open issues and100 recent merges.
There is no scoped overlap. The sole broad text hit,#1262, uses “flag-set” to
describe unrelated capacity-clamp behavior at0x4f050a0 and never names this leaf.
The full inventory/classification is retained in final-overlap.json.gz.
