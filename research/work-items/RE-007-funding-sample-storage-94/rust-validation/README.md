# Authored Rust value implementation validation

This phase follows the separately frozen static proof and pre-source corpus.
`SOURCE-FREEZE.json` binds the actual standalone crate, actual Cargo-generated
lockfile, input-only driver, build harness and installed toolchain payload pins
before the first source compilation. Results are not claimed until observed.

The driver accepts only the frozen input protocol on stdin. It imports the
public crate, applies the function, and writes all resulting active state in
canonical unsigned key order. It has no expected-file/oracle access. Only the
external Python comparator reads expected output, with exact byte equality and
missing/extra/changed/reordered/duplicate-row controls.

`build.py` requires a known source-freeze SHA, the installed pinned Rust 1.94.1
toolchain directory, a fresh direct child of canonical `/tmp`, and a private
path-mapping file outside the packet:

```sh
python3 research/work-items/RE-007-funding-sample-storage-94/rust-validation/build.py \
  --toolchain PATH_TO_INSTALLED_1_94_1_TOOLCHAIN \
  --out /tmp/funding-storage-build-UNIQUE \
  --private-map PATH_OUTSIDE_PACKET \
  --source-freeze-sha APPROVED_SOURCE_FREEZE_SHA256
```

The harness resolves `/tmp` and every build path before Cargo-config ancestor
checks and compiler path remapping. It copies only the admitted five component
files and the pinned driver; each copied snapshot is compared to the freeze
before compilation and checked unchanged afterward. Source mutation controls
alter only the declared library text in separate private copies.

Builds use fresh Cargo home, offline/locked Cargo, an explicit environment and
no inherited wrapper/compiler flags. The actual crate's debug/release tests,
format checks and Clippy run. Two separate clean directories each build debug
and release artifacts and produce every frozen output. Raw rlib/client identity
comparisons are reported without masks; if paths or host linker details still
cause differences, those remain visible rather than being called reproducible.
Ten real wrong library sources are compiled in release mode and must each
produce at least one mismatch against unchanged frozen expectations.

Every command's stdout/stderr bytes are retained as content-addressed gzip,
including compiler/test logs and complete observed value streams. Identical
observed outputs share one raw-stream file; they are never replaced by an
expected-file reference. Command input hashes identify the frozen input stream.
Public metadata uses logical path prefixes; a separate private map preserves
the exact local command paths. Raw stream bytes are not redacted or normalized.

Toolchain bin/lib payloads are pinned and checked before/after. Selected linker,
compiler-dispatch and SDK files are also recorded; this does not make the host
OS, dyld or entire SDK hermetic. The target is the host-built active-value
projection, not the captured Linux ABI or original compiler/build identity.
Allocation/refusal/rollback, scheduler/global-order, outer min pairing and
post-loop opaque effects remain excluded by the pre-source contract.
