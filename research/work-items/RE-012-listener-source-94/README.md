# Node94 listener protocol and public Mio source-build comparison

RE-012 asks for a bounded startup path with its writes and external effects;
RE-002 asks to separate exact build provenance from inferred dependencies.
This packet resolves the complete ordinary-return behavior of the node94
listener constructor and compares it with an unmodified, licensed Mio build.

The selected target is `[0x3cd6690,0x3cd67c1)`: **305 bytes, 81 instructions**.
The source-built Mio 1.0.2 `TcpListener::bind` is **364 bytes, 94 instructions**.
The whole-function denominator is one: **0/1 raw matches, 0/1 relocation-only
matches, 1/1 unmatched**. This measured candidate does not reproduce the target
bytes. It provides a reusable public-source build and a concrete code-generation
difference for further build-provenance work.

## New findings

The existing [transport socket packet](../transport-socket-calls-94/README.md)
establishes request constants and the NodePort call chain. [CONTRACT.md](CONTRACT.md)
extends that evidence to the exact IPv4/IPv6 address bytes, all four failure
branches, errno packing, inactive output bytes, publication before descriptor
cleanup, and full output-pointer return identity. The complete body has no
private direct callee or LSDA. Its six named libc imports remain external.

The high-level Linux operation sequence corresponds to public Mio source:
`socket` → `SO_REUSEADDR` → `bind` → `listen(...,1024)`, with descriptor cleanup
after failures following creation. Valid Rust `SocketAddr` inputs are the
source comparison domain. Raw tag-width probes in the target relation do not
establish valid Rust enum representations.

The target shares `socket` and `setsockopt` between address families. The built
candidate duplicates those calls in IPv4/IPv6 branches: seven target call sites
versus nine candidate call relocations. The [comparison](source-build/comparison.json)
retains every selected byte and actual relocation. It masks only four-byte
external GOT displacements and requires import identities and offsets to match.
No instruction, immediate, internal branch or register field is normalized.

Mio 1.0.2 is a tested source candidate, not an identified original version.
[Neighboring-version counterchecks](source-version-countercheck.json) show that
the four relevant source files are identical in 1.0.1 and 1.0.2. The selected
Linux functions also remain unchanged in 1.0.3. A `mio-1.0.2` path elsewhere in
the target supports the presence of that package label, not unique attribution
of this function. The older 0.8.11 macro distinguishes only `-1`; the target and
1.0.x reject any negative i32. That distinction concerns artificial import
outcomes and was not tested by executing an invalid file descriptor.

## Evidence and reproducibility

- `static/authority.json` binds the authenticated target, 32 exact byte ranges,
  five complete FDEs, named import records, and the scoped caller census.
  Primary code accounts for 305 bytes; the four complete caller contexts account
  for another 23,805 bytes and are not counted as recovered implementations.
- Complete GNU and LLVM exports agree with independent Capstone decoding.
  The primary 81 instructions require no prefix joins. Context-only LLVM LOCK
  prefix joins are explicit in the authority record.
- [source-build/README.md](source-build/README.md) contains pinned official
  archives, licenses, exact source copies, build options, commands, failed and
  successful logs, and an offline recipe. Two builds produced identical Linux
  object and library hashes. The initial `deny(dead_code)` failure is retained;
  the only build adjustment was dependency lint capping with `--cap-lints allow`.
- `manifest.json` hashes all published packet files except itself. It is a
  consistency inventory, not an external signature or substitute for the full
  target digest and official archive checksums.

The candidate is also registered in `research/byte-windows.json` as
`comparison_mode: extent-mismatch`, with its full 364-byte source extent and
`dependency: mio`. Existing aligned byte counts remain unchanged. The generated
catalogue lists this unmatched candidate separately, without treating missing
alignment as zero measured byte equality or assigning first-party credit.

This required a bounded registration fix: the base comparator rejected the
actual unequal extents, while its source slicing and dependency whitelist could
not represent this candidate. [The reproduced blocker](validation/registry-blocker.json)
records the base revision and actual rejection. The loader now authenticates
the complete declared extent and separates it from aligned comparisons; the
generator renders that distinction. This tooling change supports the measured
RE-002 result and does not alter the existing comparison arithmetic.

From the repository root, with the existing node94 LFS artifact materialized
and the repository Python dependencies installed:

```sh
python3 -O -B research/work-items/RE-012-listener-source-94/verify.py
```

This authenticates the packet and target, rechecks all static bindings, runs
114 static controls (113 below digest admission plus whole-image truncation),
and replays the five source-comparison controls. Python 3.14 and Capstone 5.0.7
were used. Ordinary replay consumes retained disassembly exports; GNU and LLVM
are needed only to create new exports. The original static recording commands
retain the earlier local packet name; the verifier was moved unchanged except
for removal of an unused optional protocol-freeze check. No protocol corpus or
native Rust observer is part of this submission.

To authenticate the source-built side externally, run `source-build/build.py`
with its three pinned archives and Rust 1.94.1, then `source-build/compare.py`
against the full authenticated target and resulting Linux object. The selected
export verifier alone establishes internal consistency, not whole-object
provenance. The build recipe and full-target comparator were both run.

## Validation and limits

Base commit: `e5c9b6436876b2a4a39daef813171f9879317699`.
Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`make doctor`, `make verify catalogue-check reproduce`, and all 56 focused
`tests.test_socket_calls_static`, `tests.test_node_port_static`, and
`tests.test_fde_extents` tests passed; retained logs are in `validation/`.
The repository sweep at `b9e9115f25f3787c7c2ea865566cd77ba8149caa`
attempted all 971 test files: 15,455 reported tests, 73 skips, and two file
failures because `LLVM_OBJDUMP` was unset (`llvm-objdump` was not on PATH).
The original `make verify test catalogue-check reproduce` exited 2 at `test`.
Setting `LLVM_OBJDUMP=/usr/bin/objdump` resolved both errors and four related
LLVM skips: all 71 tests across those six files passed. Replacing their
initial results gives 15,480 reported tests, 69 remaining skips, and no
unresolved failed files; this is not a second full-suite run. The remaining
skips include optional artifacts/providers, native-platform requirements and
captured-execution opt-ins. `make verify catalogue-check reproduce` then
passed separately. [The validation record](validation/repository-checks.json)
retains per-file results, original failure traces, retry logs and hashes.
No hosted-CI pass is claimed. Initial setup checks exposed an unmaterialized
pinned reference LFS file and a stale Git LFS
stat cache; materializing the authenticated payload and refreshing unchanged
filtered index entries resolved them. Reference commits and contents stayed
unchanged.

The analysis used insane-research's independent source review, counter-search,
claim ledger, and final validators. The source and byte records above are the
reviewable evidence; plugin status is not proof of binary equivalence.

The original crate graph, features, compiler options, ABI and integration remain
unresolved. Runtime registration, peer transport, full networking, component
completion and a source-built node are not established. In this listener
experiment, no captured binary, listener or socket was executed; the reviewed
libc host configuration helper ran only to emit build cfgs. No milestone or
completion gate is changed.

New analysis and scripts are MIT. Copied Mio, libc and Rust materials retain the
license notices under `source-build/`. Captured target bytes retain their
existing artifact provenance and rights.
