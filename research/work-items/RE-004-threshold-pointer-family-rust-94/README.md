# RE-004: complete node94 threshold pointer family in independent Rust

Question: reconstruct the full RAX/RDX relation of the threshold-only leaf and
its two flag-gated neighbors, including ordered runtime-byte requirements and
load-biased addresses. Component: foundation, bounded additional research
under RE-004; no component/progress gate is advanced.

Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Target: node94,
91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF virtual addresses. Node115 and visor are not
semantic targets. Pinned reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged; inferred unlicensed
source was neither copied nor treated as authoritative.

## Result and scope

`src/node94-threshold-pointer-family` is an independently authored safe no_std
Rust library, built directly with rustc. It implements one family of three
complete leaves at 0x54d76e0, 0x54d7700 and 0x54d7740, totaling 127 bytes and
34 instructions. PROOF.md gives the exhaustive full-u64 relation, ordinary
memory/normal-return premises, exact early-return RDX preservation and new
Option-based admission behavior. No source-level table type or logical extent
is recovered. Returned numeric addresses are never dereferenced.

The earlier `foundation-threshold-table-pointer-select-94` packet documented
only the first leaf and explicitly excluded its adjacent pair. This packet
preserves that evidence and adds the coherent Rust family, all three actual
FDEs, complete data-reference context, dynamic global-read ordering and native
qualification. The two .bss flag bytes are supplied runtime observations;
NOBITS zero fill is not substituted for live state. The code has no helpers.

## Evidence and reproduction

`verify_static.py` parses the target, closes the three bodies/FDEs, compares
GNU/LLVM/Capstone bytes and boundaries without masks, checks 7/13/13 padding
bytes, all branch/return edges, three unique entry naming slots and all 80,300
RELA records. Whole-.text E8/E9 scans find no candidate to these entries;
this is not a complete xref or reachability census. Flag .bss/PT_LOAD mapping
and address-only result mappings are bound. All 44 structural corruption
controls are rejected independently of the top-level target digest check.

The oracle/static evidence and 208,608 input/expected rows were frozen before
Rust existed. Every member covers all 65,536 byte pairs, plus missing-observation
partitions, each index bit and threshold neighbors, RDX preservation and address
wraps. Each profile has 206,883 admitted observations and 1,725 API refusals.
Opt0/opt3 and repeat builds match all 834,432 observations: 827,532 admitted
projections and 6,900 refusal checks. Library, client and output hashes repeat
at each optimization. All 23 compiled controls fail the comparator, including
eager/missing reads, signed or truncated bounds, flag classes and RDX errors.
Three native unit tests per profile, malformed-input and comparator corruption
checks pass. The input-only client never receives expected outputs.

The compiler is the actual installed rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`;
host aarch64-apple-darwin, edition2024, warnings denied, overflow checks on,
one codegen unit, panic abort for value builds. Native target instructions
were never executed or emulated. This is output-relation qualification on
new Rust, not original compiled-byte identity or whole-node equivalence.

```sh
python3 -O -B research/work-items/RE-004-threshold-pointer-family-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-threshold-pointer-family-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/threshold-pointer-replay
```

The output directory must be new. The exact compiler path can differ, but the
validator checks its binary hash/version. GNU2.47.20260726, AppleLLVM17 and
Capstone5.0.7 produced the retained static listings; their text does not replace
raw-byte equality. `native-commands.json` records exact arguments and stream
hashes. `native-streams.json.gz` contains all 184 stdout/stderr streams in a
lossless content-addressed archive (gzip level1, mtime0). Every decoded payload
and its name-to-hash binding were audited. `mutant-preflight.json.gz` retains
all23 successful metadata compilation commands and their generated controls.

## Failures and repository checks

The initial validator's `gated_bias_missing` control failed to compile because
an integer method receiver lacked a type. This affected only generated wrong
code. Its preliminary check failed too; the shell still entered native
qualification. The initial four correct builds had matched before the mutant
failure. `initial/` retains the original validator, all78 native command records,
213 initial stream/source entries and traceback. The correction adds an explicit
u64 cast to that control; library, driver, static record, oracle and frozen
expectations remain unchanged. The final fresh run above completed successfully.

`make doctor verify catalogue-check reproduce` and rustfmt passed.
The first focused command passed26 tests but named a nonexistent
`tests.test_gnu_disassembly` module, so it exited unsuccessfully. Its full
failure is retained in `repository-checks.json.gz`. The corrected command uses
`tests.test_gnu_binutils_tools`; all29 focused tests passed, with raw outputs archived.
No repository code was changed for that invocation mistake.

The separate shared baseline attempted 971 files /15,462 reported tests /69
skips. Its exit2 was due solely to three disk-full errors; all20 affected tests
passed isolated retries after verified local storage consolidation. See
`shared-baseline-result.json`. This is not a successful whole-sweep repeat or
full-suite run on this head. No skipped Linux qualification, hosted CI pass or
merge is claimed. All generated progress gates and imported pins are unchanged.

## Independent review

A separate reviewer read the complete Rust/proof and independently parsed the ELF headers and all80,300 RELA records without importing packet code. All127 body bytes, three unique slots and both NOBITS mappings were authenticated. A literal flag-action matrix and unsigned carry-out comparison recomputed all208,608 expected rows with zero mismatches. It found4,859 successful selected-address-zero cases and1,035 above-bound missing-second refusals. The portable `verify_independent.py`, review hashes and qualification record are retained. The reviewer also reran all44 static controls; no native replay is implied by that review.
