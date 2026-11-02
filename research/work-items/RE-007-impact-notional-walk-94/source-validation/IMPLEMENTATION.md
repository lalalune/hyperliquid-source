# Supplied-book impact and premium implementation

The new dependency-free MIT component `src/node94-funding-premium-values`
implements the complete qualified supplied-state operation: two actual ordered
entry views over one shared slot slice, impact walks, either premium formula,
and one selected producer record. `evaluate(Input)` returns the active premium
bits and both integer impacts, or absence with the original raw oracle fallback.
This is an additive phase of existing PR1422; the original published20 files and
pre-source32 files remain byte-for-byte unchanged.

Read the [pre-source contract](../pre-rust/CONTRACT.md),
[native proof](../pre-rust/PROOF.md), and fresh
[integer source proof](SOURCE-PROOF.md) for the conditional relation.
[Source/build admission](BRIDGE.md) explains the independent oracle, actual graph,
client and isolated reproduction command. The source proof covers positive
fractional binary64 denominators explicitly; no pending funding-rate dependency
or its narrower integer-count proof is used.

The library preserves native-width fields, signed-key magnitude, chain saturation,
full-product rejection before partial fill, actual entry order, sequential rounding,
optional division before clamp, and raw active/fallback record fields. It uses
u128 arithmetic and exact significand rounding, with no host floating arithmetic,
allocation, unsafe code, callback, file access or captured execution. Scale
admission precedes oracle-zero bypass. Both ordinary impacts are computed before
either is tested for zero. Raw target0 and reached cycles are explicitly new safe
refusals outside the corresponding native ordinary-return premises.

## Observed author qualification

The exact source freeze
`6a8946d38334d59c5f2422bbb8d80984a8d3f77454e4ae2fe69d2827726c414e`
preceded compilation. The independent coordinator source/build gate
`653586d9251b6b5f12c8a7fb021de8fbe31f02d8827045ba64f4bd8dc77ffb39`
then authorized the frozen harness. The first author attempt completed with no
required failure. No source, client, harness or expectation amendment was needed.
The earlier six preparation commands generated the actual offline lock and graph;
they did not compile a candidate.

| Observed check | Author result |
| --- | --- |
| Child commands | 198 completed:175 exit0 and23 expected exit2 refusals |
| Tests in each debug/release profile | 3 private arithmetic tests and10 integration tests passed |
| Correct complete output streams | 4, each6034 cases and0 differing rows |
| Actual compiled mutations | 24 detected in both debug and release, each a complete6034-frame run |
| Mutation scope | 22 ordinary value variants and2 new-safe-policy variants |
| Comparator corruptions | 10 rejected |
| Malformed input | 22 cases and one extra argument refused without partial value output |
| Valid empty input | Accepted with empty output |
| Actual source/client copies | 26 independently admitted source trees and26 client copies |
| Static replay | Actual post-source198-control native/corpus verifier matched its frozen JSON |
| Raw evidence | 396 stdout/stderr references,109 unique gzip streams,117 complete receipt files |

Both clean roots used the same relative component layout and canonical path
remapping. The debug and release rlibs were byte-identical between those roots,
and the release clients were byte-identical. The debug clients differed.
These are raw comparisons with no masks or normalization; there is no claim of
identical debug executables or a hermetic compiler/SDK/OS reproduction.

The exact [results](qualification/results.json),
[command log](qualification/commands.json),
[incremental observations](qualification/build-results.json), and
[author archive audit](AUTHOR-QUALIFICATION.json) retain the actual outcomes.
Every copied public receipt equals its private original byte-for-byte. Each raw
stdout/stderr reference points to a deterministic content-addressed gzip file;
`gzip -dc qualification/raw/HASH.gz` reads the original stream. The metadata's
logical path mapping is declared; raw outputs are never rewritten to hide paths.
Actual compiled binary files remain private, with their exact identities recorded.

The48 mutant streams are actual compiled runs, distinct from the22 mathematical
false-model witnesses frozen before source authoring. No compiler error, panic,
timeout or incomplete output was counted as a semantic kill. The policy-only
second-cycle witness does not prove ordinary native call order from outputs;
that order is separately established by source review.

## Scope and preserved chronology

The implementation accepts supplied logical views and selected metadata/set
values. Native correspondence still requires valid stable native structures,
normal and preserving helper returns, exact copy/allocation/frame contracts and
the frozen ISA/rounding premises. It does not prove scheduler completeness,
lookup/hash implementation, live economic units/policy, all-asset settlement,
native source types/layout, ABI or original-compiler identity. The host integer
implementation itself does not depend on a floating control register.

The original published distribution, pre-source expectation freeze and source
freeze remain separate historical stages. This qualification appends receipts;
it does not revise earlier promises to fit observed output. The source README
and source-phase BRIDGE describe their historical pre-build state, while this
entry point records the completed author qualification. Coordinator review and
its independent-run receipts may be appended separately without changing the
author manifest or historical freezes. No Git or publication action is asserted
by this author record.
