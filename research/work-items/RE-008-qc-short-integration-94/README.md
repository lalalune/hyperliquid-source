# RE-008: combined FD outcomes, byte field and row assembly

This integrates the accepted short-input extension into draft #1509's public
head `35d44f7130bc029b30723e7464ac7d8ff3644a40`. Source commit
`83d1ea44bc02e3148f536bfbeaf2d765fd229a27` adds the outcome API to the
existing `qc_fd_group` module and a fourth input-only example. The component's
manifest, lockfile and dependencies are unchanged. The original bool function
remains byte-identical (1,016 bytes, SHA-256
`6550a8bfdfca51027a202188ecb459e1c7bee638cf09e1d482e03fa382e2e3c7`).

## Fresh combined checks

All selected examples have exactly 13 compiler-read project Rust files: the 12
crate modules plus that example, excluding the other three examples. Each
selection has 15 source/manifest/lock pins; the union contains 18 files.

| Selected client | Exact matches per opt0/opt3 | Operative compiled mutants, disagreements per profile |
| --- | ---: | --- |
| Byte field |2,572/2,572|516,3,515,513,769,1528|
| Complete FD group, original bool API |8/8|7,8,8,8,8,7|
| FD outcome API |44/44: 36 new errors plus 8 prior successes|8,8,8,8,32,28,44,36,36|
| Row assembly |3/3 full 104-byte frames|Five separate static native controls; no compiled-mutant claim|

The short-input result exposes only the group tag qword, kind byte, need qword,
charge, pointer advance, remaining length and suffix. Row error forwarding is a
driver-only active-field projection, not a library row decoder or error ABI.
No inactive error qword/payload or full 40-byte error image is compared. The
original complete group's successful 40-byte view remains separately tested.

Cargo all-targets passes 51 tests per profile and builds all four examples.
Focused Python passes 12/12. All four native verifiers pass; `make doctor`,
`make verify`, `make catalogue-check` and `make reproduce` exit 0. Pinned reference
contents were authenticated and materialized from existing local stores with
lazy fetch disabled; LFS filters were command-local and only verified index
stat metadata was refreshed. No input/pin/persistent configuration/catalogue
edit was made. Full repository `make test` was not rerun or claimed.

## Disk failures and recovery are separate records

The initial concurrent field/success/short verifiers stopped with Cargo 101,
`No space left on device`. They are environment failures, not semantic controls.
The assembly verifier had already passed and was retained without restart.
The three failed verifiers then passed in fresh directories, sequentially, with
invocation-local `CARGO_INCREMENTAL=0` and free-space guards. No source or tool
script change was needed. Completed failed attempts' incremental caches alone
were removed after hashing 578 preserved source/log/dep-info/client files; their
raw failures and preservation receipt remain available. Later checks were
sequential and guarded as well. `RESULTS.json` pins these actual receipts.

## Historical evidence and limits

All five prior packet directories are byte-identical to public head `35d44f71`.
The accepted short packet's source, frozen data, tools and RESULTS are unchanged
from commit `d3893eb8`; only its obsolete uncommitted/publication wording and scoped
manifest were corrected. Earlier source pins and outcomes remain historical;
this record supplies the expanded source closure without rewriting them.

Raw current receipts are under ignored `work/qc-four-integration/`. Their hashes
identify actual streams, commands, source snapshots, tool versions and built
clients; they are not target-machine-code matches. FD outcomes are conditional
on admitted mode 1 entry and FD markers up to the first short field. Other
markers/modes, native reservation failures, source error layout, ABI/lifetime,
native store timing, complete QC-row reachability, unwind and cryptographic
validity remain unqualified. No captured executable was run or emulated. All
full component gates remain false; final independent review precedes publication.
