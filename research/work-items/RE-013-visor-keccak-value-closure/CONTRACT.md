# Existing-provider qualification contract

The intended executable qualification uses the existing merged MIT
`node94-action-signable` Cargo component, exactly its public
`keccak256(message: &[u8]) -> ConnectionId` and `ConnectionId::as_bytes()` API.
There is no new production API, Visor wrapper, duplicate hash implementation,
filesystem adapter, streaming state, or standalone fake workspace. Its actual
11-file crate tree and repository MIT license are fixed in `BASIS-PINS.json` at
main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. This source already existed
before the independent corpus; chronological independence is claimed only for
the new corpus versus any future input-only qualification client.

For every finite byte slice admitted by Rust's actual slice domain, the value
contract is 32 Keccak-256 bytes: 136-byte rate, 24-round Keccak-f[1600], delimiter
1, final padding bit 128 in the last rate byte, and little-endian lane output.
Empty input and embedded NUL are ordinary messages. There is no UTF-8 or
zero-termination constraint. This safe provider's allocation/length admission
is not evidence for the original reader's error ABI or filesystem behavior.

The native success relation additionally requires the explicit valid-memory,
nonaliasing, stable reader-result, imported-copy, opaque cleanup/error-helper,
red-zone, no-unwind and normal-return premises in `PROOF.md`. It projects only
the initialized one-shot 32-byte value. Arbitrary rate/cursor/phase, generic
update/squeeze, read failures as source-language errors, and cleanup internals
are outside the provider qualification. The wrapper's raw error tag/word and
success-store order are independently documented, with no proposed Rust API.

After a separate root source gate, a new input-only client may depend on this
real local crate and print one digest per request. Only the comparison harness
receives `expected.tsv.gz`. Neither client nor library may read expectations,
semantic provenance labels, official answers, captured bytes, oracle code, or
the target ELF. The existing crate's own tests/fixtures are baseline context;
the independent value comparison must not be replaced by those tests.

Before any compilation, admit the complete actual Cargo graph, path dependency,
symlink destinations, lexical and canonical ancestor workspace/config files,
lockfile, hooks/build scripts, environment and exact toolchain payloads. Use
offline/locked pinned builds of the real existing crate and actual client in
both debug/release, retaining all raw streams and failed attempts. Source-copy
semantic mutants must compile and emit all inputs; syntax/lint/build failures
are not value kills. No client or library compilation is authorized by this
pre-code packet alone.

Proposed source-copy mutations cover delimiter 6, missing first/final padding
bit, omitted empty/exact-rate final block, rate boundary, capacity absorption,
word/output endianness, 23 rounds, a round constant, theta neighbor/rotation,
rho rotation, pi destination, chi negation/order, iota lane, and output lane
selection. Exact syntactically valid coordinates require later source admission;
this list is a plan, not evidence that any compiled mutant ran.
