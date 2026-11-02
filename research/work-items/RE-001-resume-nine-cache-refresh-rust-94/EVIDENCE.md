# RE-001-resume-nine-cache-refresh-rust-94: Cache refresh with ordered stores and post-call reload

- Task / research allocation: RE-001 / foundation; bounded independent Rust.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: Linux x86-64 node94; 91,774,280 bytes; SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, not guessed Ghidra or runtime addresses.
- Source: `src/node94-resume-nine-cache-refresh/lib.rs`.
- Status: finite static-observation/compiled-Rust agreement; no target execution,
  instruction emulator, native ABI/fault equivalence or compiled target-byte claim.

## Missing code and retained semantics

The base contains the predecessor static packet/checker, not an independent
Rust implementation at this new source path. The following memory/call/register
projection is recovered from its authenticated instructions. It is one bounded
outcome, not a new complete-node or full-component claim.

The complete FDE is `[0x5172e20,0x5172e49)`. Preserve the following
order, rather than applying the old packet's value formula to preloaded fields:

1. Read the second pointer at object+8. Offer the opaque call at0x5172b00
   with `(second_before_call, incoming_RSI, incoming_RDX, incoming_RCX)`.
2. Store the callback's qword result at object+0x20.
3. Reload the second pointer from object+8. Read the link at second+0x18.
4. Store one byte at object+0x28: one when the link differs from its own
   wrapping address, otherwise zero.
5. Raw RDX is second+0x18. Raw RAX is `(second & ~0xff) | flag`, since the
   reload supplies RAX and SETNE changes only AL. This is a register projection,
   not an assertion of an application-level return type or meaning.

The callback can change the second-pointer slot, so caching the first pointer
changes the actual caller behavior. Also, when second=object+8, the link-read
address is object+0x20: it must see the cache qword just written, not an older
link value. Cases include both interactions, byte-only flag stores, guard
bytes, wrapping addresses, full-width values and checked missing spans.

The helper's body and private effects remain unresolved. The Rust API accepts
an explicit callback boundary with deterministic fixture side effects; it does
not replace that helper with an invented source implementation. Other native
registers, stack/control aliases, concurrency and faults are outside scope.

## Inputs and independent evidence

`ORACLE-FREEZE.json` was written before the new Rust source path existed.
It binds the static admission implementation and result, Python observation
contract, input-only corpus and compressed expected observations, plus the
unchanged predecessor checker and its supporting files. `admission.py` checks
the complete captured target size/SHA and predecessor static evidence, then
decodes the actual retained raw FDE/CIE records from `.eh_frame`: signed
PC-relative initial locations and unsigned extents under the recorded CIE
encodings. It records the exact raw bytes and intervals, including the relevant
neighbor boundaries. This supplements, rather than reinterprets, older frame
text. `target.gnu.txt.gz` retains fresh bounded GNU disassembly.

The Python oracle uses a byte dictionary and unbounded integers reduced at
explicit u64 operations. The separately authored Rust client uses BTreeMap
bytes and native wrapping operations. Initialization writes listed slots in
order, inserts unmapped adjacent guard bytes, then removes selected spans.
Consequently aliases affect the bytes actually loaded. Callback effects, where
present, are explicit input fixtures. The client receives no expected results.
Records include success/refusal, only the stated raw register projection,
ordered logical operations and the complete final mapped byte image.

The corpus has 1024 records: 215
successful byte views and 809
checked-view refusals. These denominators are stated separately: checked
refusals are new safe-API behavior, not captured fault observations. A write
primitive preflights its whole span; earlier successful writes are preserved
if a later primitive refuses. No MMIO, native partially faulting store,
arbitrary concurrency or control-stack alias equivalence is asserted.

## Actual compiled checks

rustc1.94.1 / LLVM21.1.8, edition2021; dependency-free rlib plus a separate
input-only native client. No Cargo graph/workspace/lockfile is invented.
Opt-level0 and opt-level3 are each built twice. All 1024 frozen
records match on every execution; same-profile rlib/client bytes repeat
identically. `qualification/result.json` binds source, qualifier, compiler,
commands, artifact hashes, counts and actual witnesses. Primary and mutant
outputs are retained compressed. Command stdout/stderr streams are retained
with local path strings replaced by `<REPO>`/`<HOME>`; numeric comparisons are
not changed. `rustfmt --edition2021 --check` passes.

Separately compiled semantic controls:

- `skip-postcall-reload`: 457/1024 records differ, including 191 where both executions succeed. Normal process exit; compressed output and first successful witness retained.
- `invert-self-flag`: 323/1024 records differ, including 215 where both executions succeed. Normal process exit; compressed output and first successful witness retained.
- `widen-flag-store`: 323/1024 records differ, including 50 where both executions succeed. Normal process exit; compressed output and first successful witness retained.
- `erase-rax-high-bits`: 215/1024 records differ, including 215 where both executions succeed. Normal process exit; compressed output and first successful witness retained.

Every control changes successful-view behavior, not merely a new refusal.
These finite checks are not a formal proof over all u64 states. No raw or
normalized target-code comparison, whole-ELF identity or target behavior under
execution is claimed. Inferred unlicensed source was not read/copied into the
implementation. Imported evidence, pins, catalogues and progress gates stay
unchanged; no first-party byte or ownership denominator is increased.

## Reproduce and remaining repository checks

On Linux x86-64 with authenticated pinned inputs and rustc1.94.1 available:

```sh
python3 -O research/work-items/RE-001-resume-nine-cache-refresh-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-resume-nine-cache-refresh/lib.rs src/node94-resume-nine-cache-refresh/client.rs
make doctor verify catalogue-check
make reproduce
make test
```

The qualifier and rustfmt commands above were actually run successfully.
Shared repository checks are pending parent coordination for this batch.
No complete `make test`, per-head full-suite pass, hosted CI, container,
network, chain, deployed service or production-readiness success is claimed.
The PR remains a scoped draft until the remaining qualification is resolved.

Next step: independently review the bounded projection and resolve the stated
layout, ownership, native calling convention and helper/consumer gaps before
integrating this fragment into a native implementation.
