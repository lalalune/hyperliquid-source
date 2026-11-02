# Actual authored Rust validation

The first source build passed without a source/harness amendment. The immutable
source freeze is SHA-256
`15ac993d8e535e095d510b5868692fde23895f436d30b57bbce0ce071837be6b`;
it binds all32 actual package files plus the input-only driver and build harness.
The earlier pre-Rust freeze remains unchanged at
`d143e3e0c5d66f0503388250543523754fdd6c13a5d88104809256955ee370b3`.

Using rustc1.94.1 (`e408947bf`,2026-03-25), both debug and release passed36
existing library tests and7 new integration tests. All1,141 frozen inputs
matched the expected full preimage length, every byte and digest in both
profiles and both clean same-path rebuilds. Rlib and client SHA-256 identities
also matched each profile's clean rebuild without masks. Eight malformed
frames per baseline profile were rejected, and changing the inert ID preserved
the actual values. Selected library/integration-test clippy passed with warnings
denied. No old evidence-contract integration test or broad repository suite ran.

All17 deliberately wrong source implementations compiled and produced a
different result in both profiles. Mismatch counts were identical across the
two profiles:

| Source change | Mismatching cases |
| --- | ---: |
| Tag one |1141|
| Clamp negative seconds |487|
| Truncate negative-year division |232|
| Wrong epoch by one day |1141|
| Raw seconds word |684|
| Nanoseconds divided to milliseconds |457|
| Reverse transaction hashes |9|
| Reverse QC votes |9|
| Omit QC votes |226|
| Collapse present-empty TC |1|
| Timeout signature after body |212|
| Raw65 signature |343|
| Big-endian signature limbs |200|
| Inactive padding as final byte |333|
| Zero claimed proposer |1141|
| Hash only one rate block |232|
| Drop a byte at exact rate multiples |3|

The126 recorded commands all exited0. [receipts/results.json](receipts/results.json)
has SHA-256 `91546ffab0a5082ef2b4a0958b63322c7de7096e562d3ce003419615688967c1`;
[receipts/commands.json.gz](receipts/commands.json.gz) has SHA-256
`7ada510ec7f7ee3cf883fab52085c91234ab14d11de377869291acc4db5dc2fe`.
All252 raw stream references,68 unique raw archives and38 full output archives
were independently rehashed and their mismatch counts recounted after the
build. [RECEIPT-CHECK.json](RECEIPT-CHECK.json) records that audit. Raw streams
are retained unchanged; metadata alone replaces local paths with logical
ROOT/WORK/TOOLCHAIN/HOME labels. Compiler path-remapping flags were active
during the builds. No public personal absolute paths were retained.

The real three-package manifests/lock, absent build hooks/configuration,
lexical and canonical temporary ancestors, explicit environment, tool versions
and six tool executable hashes are in the result receipt. Source files and
tool identities were checked again after all builds. The independent root replay
also passed all126 commands: all38 value output streams matched the author's
bytes, and its clean same-path artifacts matched within that replay. Across the
author's and root's different build directories, **both the rlib and client
bytes differed in both profiles**. The cause was not established; no
cross-directory raw artifact identity is claimed and no cosmetic rerun was
performed. Root additionally checked its97 toolchain payload files before and
after execution. No host OS/SDK hermeticity is claimed.

These are finite comparisons of newly authored Rust with expectations derived
before implementation. They do not execute the target, close opaque allocation
or error paths, establish signature validity, prove native ownership safety, or
replace the conditional proof and credited Keccak identity. No target program,
captured instruction evaluator, network service or signing operation ran.
