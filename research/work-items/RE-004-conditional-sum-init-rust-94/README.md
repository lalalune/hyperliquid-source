# RE-004: complete signed-low32 initializer

Target node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
This adds independently authored Rust to the historical foundation
conditional-sum-init research. It does not infer a source constructor, field
meaning, application protocol or completed component gate.

The complete leaf `[0x5475e80,0x5475ead)` is 45 bytes / 11 instructions, followed
by three separate INT3 padding bytes. Low32 RDX is sign-extended to a full qword
and added to RSI modulo 2^64. The conditional RSI selection is redundant for
every raw input: when low32 RDX is zero, its sign extension is also zero.
The four output qwords are `[0,sum,0,extension]`; full RAX is 1, RSI is the sum,
and full RDX remains unchanged. PROOF.md establishes the complete input domain,
safe span checks and final-state equivalence of the four disjoint stores.

There are no data reads, helpers, static constants in memory or imports.
GNU/LLVM/Capstone bind the complete leaf, both complete caller FDEs and exact
CIE/padding records. The three windows total 8,547 bytes / 1,718 instructions.
Both incoming E8 candidates are decoded call boundaries; the whole-.text E8/E9
scan finds no other direct candidate into the leaf/padding. All 80,300 RELAs
contain no relevant naming entry or code writer. Indirect reachability and the
callers' surrounding behavior are not claimed complete. All 18 static
corruption controls reject. No static qualification failure occurred.

## Independent expectations and qualification

Before Rust, the oracle froze 9,690 cases: 8,709 admissions and 981 refusals.
It uses unsigned remainder/subtraction for signed interpretation, unbounded
addition and remainder, and an immutable address dictionary with byte patches.
The input-only Rust client never receives expected outputs. Fixtures include
4,337 negative low32 values, 1,836 high-only RDX values, 1,224 sum wraps,
3,603 unaligned destinations and 2,478 exact-end spans. Those counts overlap.

Four native builds/repeats at opt0/opt3 match all 38,760 full status/register/
image observations, with identical same-option artifacts. Three unit tests pass
per optimization. All 22 compiled wrong variants differ: 17 change successful
values, four change admission, and one changes 564 refusal images. The last
variant tests only the added safe refusal contract. All mutation spellings
passed metadata compilation first. No native qualification failure occurred;
the source, pre-Rust oracle and frozen expectations stayed unchanged.

The 8,036,838-byte lossless archive retains 178 exact stdout/stderr streams from
89 commands. `verify_recorded.py` checks every payload hash, source identity,
command outcome, complete result and effective mutation category. Completed
compiler artifacts and duplicate stream files are removable only after their
hashes/equality against the retained result/archive are recorded.

An independent reviewer checked the full source, proof and fresh disassembly.
Its byte-sign-fill, bytewise-carry and original-store-order snapshot oracle
matches all 9,690 cases without importing the author's oracle. It manually
checks ELF/FDE/CIE records, both complete callers, incoming call boundaries and
all RELAs. The parent reproduced its exact report. `peer/README.md` describes
that review; no blocker or discarded review failure was found.

Doctor, verify, catalogue-check, reproduce, 29 focused predecessor/FDE/GNU tests
and rustfmt passed. `repository-checks.json.gz` retains exact commands/streams.
The separate shared baseline attempted 971 files / 15,462 tests / 69 skips.
Its original exit2 had three disk-full errors; all 20 affected tests passed an
isolated retry. `shared-baseline.json` retains the result and log hashes.
No successful full-sweep repeat, per-head full suite or hosted CI is claimed.

## Reproduction and limits

```sh
python3 -O -B research/work-items/RE-004-conditional-sum-init-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-conditional-sum-init-rust-94/verify_recorded.py
python3 -O -B research/work-items/RE-004-conditional-sum-init-rust-94/peer/verify_independent.py
python3 -O -B research/work-items/RE-004-conditional-sum-init-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/conditional-sum-init-replay
```

Use a fresh output directory. The compiler path may differ; the native verifier
checks rustc 1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
It builds the no_std library directly with rustc, edition2024, checked overflow,
denied warnings, one codegen unit and the system linker on aarch64-apple-darwin.
No root Cargo workspace or original build provenance is invented. Static tools
are GNU 2.47.20260726, Apple LLVM17 and Capstone5.0.7; commands bind identities.

Correspondence assumes ordinary stable memory, valid unchanged code and normal
return/control state disjoint from output storage. Wrapped output layouts,
original partial faults, native ABI/flags, MMIO, races and control aliases are
excluded. No captured binary execution, instruction emulation, original compiled
byte identity or whole-node equivalence is claimed. Pins, imports, catalogue
and progress gates remain unchanged.

The final submission scan covered 220 open PRs, zero open issues and 100 recent
merges, with no scoped match. `final-overlap.json.gz` retains the inventory.
An earlier inventory archive write failed with disk-full after the read-only
GitHub queries completed. Its exact partial bytes and error metadata are retained
in `initial-inventory-write-failure.json.gz`; the inventory was fetched and saved
again after verified duplicate cleanup. That packaging failure did not affect
the completed native, static or independent-review results.
