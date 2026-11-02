# RE-008: node115 TC cancellation, reduction and caller admission

This packet reconstructs the local cancellation and result-selection protocol
used by the node115 TC verification path. It binds both producer forms, the
actual entry/wrappers and caller, then qualifies a dependency-free safe Rust
value projection. A local first-lane error preference does not prove that the
globally earliest invalid input wins or that every item is checked.

Target: Linux x86-64 node115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Task/component: RE-008 / consensus, with directly validated RE-014 migration
input. Addresses are linked ELF virtual addresses with exclusive ends.

The seven complete subjects total 6,034 bytes / 1,206 instructions:

| Role | FDE range |
|---|---|
| 104-byte inline-row bridge | `0x5b37b70..0x5b38114` |
| 16-byte pointer-pair bridge | `0x5b3bd10..0x5b3c223` |
| Inline-row fold | `0x564c120..0x564c4ad` |
| Pointer-pair fold | `0x564c4b0..0x564c82d` |
| Initial flag and dispatch | `0x564b510..0x564b5e4` |
| Outer join routing and merge | `0x5aac2c0..0x5aac694` |
| Flat producer and cleanup | `0x5b3dde0..0x5b3df09` |

Seventeen full context bodies include the 249-byte per-row helper
`0x5942cc0..0x5942db9` and the 1,304-byte actual caller
`0x5960390..0x59608a8`. A full executable-section opcode candidate scan, followed
by containing-FDE boundary validation, finds 20 incoming sites in 19 FDEs.
After deduplication, GNU, Apple LLVM and Capstone agree on 35 complete bodies,
26,297 bytes / 5,898 instruction boundaries. Seventy-four first-order callee/data
targets have retained boundary bytes and FDE/CIE or PLT metadata; these are
opaque boundaries where their semantics are not reconstructed. Full RELA
inventory, selected data writers and all selected FDE overlaps are checked.
This does not establish complete indirect reachability or scheduler closure.

## Established relation and limits

The raw result/folder sizes are 72/88 bytes. A bridge observes cancellation before
splitting. A local fold does not check it before the first item; after successful
reduction it reads the flag, while an error stores1 and exits. Raw tag0x2f stops
the local fold before reduction. Success tag0x2e leaves the existing successful
payload unchanged. Both-error reduction retains the existing/first-lane record,
then performs the actual tag-specific cleanup of the discarded record. Both
successes at a bridge write only output byte0; a selected error copies72 bytes.

The actual per-row helper normally writes only tags0x2e or0x09. It initializes
52 bytes of a56-byte allocation before an opaque cryptographic call. The raw
fold's stop marker and extra cleanup-tag cases are a wider local domain, not
claims about this helper's ordinary reachable outputs. Its allocation tail and
inactive result bytes are not invented.

The actual caller checks maximum round, quorum and nested QC before entering
parallel verification. History query round+0x40, expected maximum+0x30 and
certificate round+0x88 remain distinct. This is materially different from the
historical node94 path used as search input. Node94 addresses, 184-byte rows,
80-byte result layout and nested-QC skip argument are not transferred.

`PROOF.md` gives native sites, universal local arguments, staged memory/order
conditions, full scalar domains and remaining opaque calls. `rust/` is a real
standalone analysis crate with no external dependencies and an unsafe-code ban.
It consumes snapshots and supplied helper/flag observations. It does not run
Rayon, authenticate certificates, emulate instructions, traverse arbitrary
native pointers or simulate concurrent scheduling. Ordinary helper returns,
valid disjoint storage, defined projected bytes and cleanup noninterference
are explicit premises. No component gate or byte-window credit advances.

## Licensed source countercheck

The official Rayon1.10.0 comparison is pinned to commit
`7543ed40c9a017dee32b3dc72b3ae819820e8366`. Selected `try_reduce.rs` and
`plumbing/mod.rs` plus both MIT/Apache notices are preserved with hashes.
They explain structural correspondence only. The node115 binary names an
unversioned `z_vendor/rayon` path. The same `try_reduce.rs` is byte-identical at
official1.12.0 commit `c9ced185ae3508246a9eb70c8407a1199bb1b77f`; inspected
split/bridge bodies are unchanged. Vendor revision, patches, source-level atomic
ordering and crate-lock identity remain unresolved. Official API documentation
also leaves the chosen error unspecified when several errors occur.

`source-countersearch.json` records the actual primary URLs, counterchecks and
failed web/API attempts. `research-handoff.json` separates binary-only findings
from external support; these sources do not independently establish private
consensus semantics. No unlicensed inferred source was read or copied.

## Qualification

`freeze.json` precedes the new node115 Rust directory and pins 15,412 independently
computed expectations: 5,096 fold, 2,048 merge, 4,000 split, 768 closure, 2,500
caller and 1,000 entry observations. It explicitly acknowledges that historical
own Rust already existed as migration input. The source-independent oracle uses
terminal-index sets/error-owner lists and predicate regions; the Rust client
receives only inputs, never expected outputs.

Rust1.94.1 opt0/opt3, each repeated, match all61,648 observations. Repeated rlib
and client hashes agree within each profile. All36 compiled semantic mutants
return normally and differ in values; four comparator corruptions and eight
parser controls have the required results. `native/` retains the exact258
stdout/stderr streams in a lossless xz JSON archive, all commands and hashes.
Offline replay authenticates those recorded observations; it does not rebuild
compiler artifacts or execute the captured node.

Nine focused test methods pass, including real target/FDE/relocation/operand
corruptions, decoder agreement, native/independent-oracle replay, comparator and
archive controls, and closed manifest inventory/symlink controls. Initial base
`doctor/verify/catalogue-check/reproduce` passes after local pinned-submodule
initialization; the original missing-module failure is retained. The final
precommit focused replay, locked/offline Cargo all-target check, and
`doctor/verify/catalogue-check/reproduce` pass; logs are retained in
`validation/precommit-checks.json.gz`. Full `make test` passed on fixed head
`2b0e3087ea11904aa9fa45a8f058f4fa76e4d523`: 77 files, 391 reported tests,
3 skips, exit0. Exact inventory, commands and streams are retained under
`validation/full-suite/`. Subsequent changes only add these records and peer
evidence/documentation; no semantic source or fixture changed. Optimized packet
replay and `make verify catalogue-check` pass after incorporation, recorded in
`validation/final-evidence-checks.json.gz`.

Independent peer review rederived all15,412 expected rows, freshly checked all
35 FDEs/26,297 bytes and selected writers, and audited the retained native
streams. `peer/` preserves its scripts, exact records, reviewer failures and
independence limits. It did not run captured code or repeat native builds.

## Reproduction

From the repository root with pinned artifacts and installed Python/Capstone:

```sh
python3 -B -O research/work-items/RE-008-tc-parallel-abort-115/verify.py
python3 -B -O -m unittest tests.test_tc_parallel_abort115 -v
python3 -B research/work-items/RE-008-tc-parallel-abort-115/export_disassembly.py \
  --gnu /path/to/gnu-objdump --llvm /path/to/llvm-objdump --out NEW_DIR
python3 -B -O research/work-items/RE-008-tc-parallel-abort-115/validate_native.py \
  --toolchain-bin /path/to/rust-1.94.1/bin --out NEW_DIR
```

Both output directories must be new. The packet verifier checks a closed
inventory, full target identity, bindings, two native decoder outputs, frozen
oracle and every retained normal/mutant stream. No historical node94 tool or
artifact is a runtime dependency. New work by 신준; coordinator attribution:
`openai/gpt-6-astra / Codex 0.166.0`. Captured execution, services, chain actions,
keys and signing were not performed.
