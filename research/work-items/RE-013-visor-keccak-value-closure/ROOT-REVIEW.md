# Independent review and actual qualification

This contribution closes the supplied-byte digest dependency in four Visor
functions and qualifies the existing merged MIT Keccak provider. It adds no
production digest implementation or wrapper. The earlier algorithm inference
in PR45 and the updater metadata work in PR1394 are credited in the frozen
proof. The file-read envelope in PR1607 remains outside this digest contract.

The original pre-code freeze and all31 files, source freeze, unchanged11-file
provider and its real external test fixture remain exact. Root static replay
passed296 controls and regenerated native/corpus evidence twice each. Independent
byte audit covered four full FDEs,3612 bytes/877 rows,15595 relocations,35 calls,
71 branches,20 data edges and136 bound fields. A separate scalar mathematical
calculation matched all2000 expectations, including256 official byte-aligned
vectors independently extracted from the pinned primary archive. These are
static and mathematical observations; the captured executable was not run.

Root and peer read the complete existing provider graph, source correspondence,
input-only client and build harness before the exact build gate. Both author
and root then completed190 commands:171 exit0 and19 intentional exit2 refusals.
Each profile passed14 existing library tests. Each run produced50 complete
2000-frame streams: six baseline/rebuild streams and44 streams from22 compiled
source-copy mutants. All50 streams match across author and root; every baseline
stream matches the independently frozen expectations. Ten comparator controls,
18 malformed batches, extra arguments and valid empty input were checked.

Root independently rehashed760 command-stream references,200 private compiled
artifact references,50 source observations and50 client copies across the two
runs. Source, toolchain payload and frozen input identities remained unchanged.
The same-path clean repeats were byte-identical. Between different build paths,
rlibs and release clients match; debug clients differ. Across corresponding
author/root artifacts,75 of100 identities match. No masks or normalization were
used, and no cause of the debug differences is asserted. Exact compiled bytes
remain private; their public hashes do not imply public distribution.

`ROOT-COMPARISON.json` records actual comparisons. `root-validation/` retains
root commands, unmodified raw streams, graph/artifact identities and separate
review/gate records. Byte-identical gzip streams may be referenced from the
author archive; original root command metadata is retained alongside the explicit
archive-path projection. Any logical path projection of review metadata is
marked and binds its privately retained original hash. Raw child streams and
compiled comparisons are never redacted to obtain equality.

`IMPLEMENTATION.md` gives the complete post-source replay command. The unchanged
pre-code verifier must run on the exact31-file copy that the build harness
constructs, preserving its source-absence check. Original phase manifests remain
historical; `PUBLIC-MANIFEST.json` binds the complete final contribution.

The native reader/import/error/cleanup, valid-memory, escaped-pointer frame,
normal-return and red-zone premises remain explicit. Neither repeated decoding
nor independent reviewers create another native target lineage. This qualifies
host implementation values; it does not establish native compiler/ABI equivalence,
live update behavior, cryptographic security or a whole Visor completion gate.
