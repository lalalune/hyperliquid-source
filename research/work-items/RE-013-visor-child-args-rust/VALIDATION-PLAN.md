# Pre-code protocol and later build admission

Only the independent mathematical generator and static native binder may run before the parent gate. Neither starts the captured executable or interprets instructions.

## Frozen stream protocol

Inputs have one ASCII line per case: `id<TAB>cells<LF>`. A cell is lowercase byte hex, `-` for a nonnull empty byte span, or `~` for None (native null-empty stop). Cells are comma-separated; `.` denotes zero descriptors. Case IDs/categories are synthetic and contain no user data. The candidate client receives only this input stream.

Expected success is `id<TAB>OK<TAB>cells<LF>`, containing only the owned resulting byte strings (hex or `-`), or `.` for zero strings. Invalid-UTF8 refusal is `id<TAB>INVALID<TAB>argument_index<LF>`. Domain and host allocation errors have distinct protocol labels; corpus byte cases fit the native descriptor domain and never intentionally trigger OOM.

A separate integer stream is `id<TAB>u64_count<LF>`; its expectation is `id<TAB>OK<TAB>24_times_count<LF>` when <=2^63-1, otherwise `id<TAB>DOMAIN<LF>`. It exercises the public admission helper used by the real library, not a test-only mirror or enormous fake slice.

The parent comparator alone loads expected streams. The input-only client must not import the oracle, fixtures, answers, answer hashes or packet code, and the library has no I/O. This is reviewed data-flow separation; it is not a filesystem-sandbox claim.

## Static and grammar controls

The binder authenticates full target bytes before parsing and rechecks pinned prior record/proof/complete-export hashes. It independently maps PT_LOAD ranges, validates every GNU/LLVM instruction byte and full-body tiling, retains raw actual FDE/CIE records and used RELA/symbol/table data. No mnemonic or hash check substitutes for the credited manual proof. Changed body/table/caller binding/FDE metadata should be rejected, including parser-level checks below the outer whole-image identity gate in the later verifier.

The generator enumerates scalar encodings from integer equations, authenticates native lead widths and uses the credited proven language. It must generate identical compressed bytes (mtime0, no filename) in two fresh output trees. Hand-derived cases test ASCII/NUL/empty, overlongs, surrogate encodings, U+10ffff, out-of-range four-byte sequences, invalid-present-byte versus truncation precedence, first-invalid argument and unobserved suffix after None. Scalar-prefix enumeration is a finite mathematical certificate, not x86 evaluation.

## Required later real validation

After source authorization, freeze all library/test/client/build-harness files before running them. Audit manifests, actual generated lock, dependencies/features, build scripts, symlinks, toolchain/linker/sysroot hashes, Cargo ancestor/config files (including canonical /private/tmp on macOS), inherited environment and subprocess commands. Use clean explicit environment with PYTHONDONTWRITEBYTECODE=1 and no registry/network updates.

Run actual pinned offline/locked debug and release library tests and separately linked input-only clients. Keep every command, status and raw output hash; large raw streams may use deterministic gzip once, with logical public paths and explicit private path mappings. Use Cargo metadata to establish the real dependency graph, not a synthetic manifest claim. Rebuild cleanly and compare same-path compiled artifacts/raw results with explicitly stated reproducibility limits.

Compiled semantic mutants must cover: accepting invalid bytes lossily, rejecting NUL, dropping empty arguments, treating empty as stop, continuing past None, reversing arguments, trimming bytes, wrong first-invalid argument index, changing None into an empty element, dropping duplicates, and descriptor-bound/24-byte arithmetic errors. Each counted mutant must compile and cause an actual frozen comparison failure; compilation failure is not a semantic control. Scope exact viable mutations after seeing production source without altering the independent corpus.

Comparator corruption tests include missing/extra/duplicate/reordered cases, wrong OK/INVALID/DOMAIN statuses, mutated bytes/order/count/index, wrong giant arithmetic, and expected-file tampering. Host allocation refusal and malformed client protocol are separate from target-grounded byte cases.

Independent root/peer review must check the source bridge, actual dependency integrity, typed pointer-zero/empty distinction, alias/ownership behavior and finite comparator. No target binary execution, ABI/byte identity, full CLI acceptance, process-spawn effect, component gate or performance claim follows.
