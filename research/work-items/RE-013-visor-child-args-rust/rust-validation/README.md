# Actual source and post-source validation

This phase preserves the complete original pre-code manifest and freeze. The
new SOURCE-FREEZE.json admits the real five-file crate, Cargo-generated lock,
input-only client, verifier/build harness and toolchain pins before compilation.
Results are reported only after actual execution of authored host code.

The final checkout uses this directory's verify.py, not the historical
verify_precode.py, which intentionally requires source absence. With a fresh
output directory and the reviewed source-freeze digest:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-child-args-rust/rust-validation/verify.py --out /tmp/child-args-replay-UNIQUE --source-freeze-sha APPROVED_SOURCE_FREEZE_SHA256
```

It admits all original 23 files and their pre-code chronology, authenticates the
source/harness freeze, runs the frozen binder/corpus directly, and compares all
12 retained files exactly. Source absence remains a historical observation.

The real build accepts the installed pinned 1.94.1 toolchain, a fresh direct
child of /tmp and a fresh private mapping path outside this packet:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-child-args-rust/rust-validation/build.py --toolchain PATH_TO_1_94_1_TOOLCHAIN --out /tmp/child-args-build-UNIQUE --private-map PATH_OUTSIDE_PACKET --source-freeze-sha APPROVED_SOURCE_FREEZE_SHA256
```

Actual Cargo metadata must show one real dependency-free lib/test package.
The harness admits all source bytes and symlinks, checks lexical/canonical
Cargo ancestors and fresh Cargo home, pins toolchain bin/lib contents/link
targets, sets an explicit environment, and builds offline/locked. Selected
compiler/linker/SDK inputs are recorded; host OS/dyld/full SDK hermeticity is not
claimed. PYTHONDONTWRITEBYTECODE=1 reaches Python subprocesses.

Both debug and release run library tests and separately linked input-only
clients against 108604 frozen collection cases and 197 integer cases. A separate
clean directory rebuilds both profiles. Raw rlib/client comparisons are reported
without masks; Mach-O debug link object paths may remain despite compiler path
remapping, and a difference is retained rather than cosmetically retried.

Fourteen distinct wrong library sources are actually compiled and compared in
both profiles. Every counted mutant must compile and mismatch a frozen value
or length stream; compilation failure is not sensitivity. Twelve exact-byte
comparator corruptions check missing/extra/duplicate/reordered rows, statuses,
bytes, indices and integer results.

The client parses only opaque case IDs and input values from stdin, invokes the
real exported functions and serializes actual results. It never reads expected
files, the oracle or answer hashes. The Python parent alone reads expectations.
Every command's raw stdout/stderr is retained as content-addressed gzip, with no
expected-file substitution. Public metadata has logical paths; a separate
private mapping records exact local paths. No target program is run or emulated.
