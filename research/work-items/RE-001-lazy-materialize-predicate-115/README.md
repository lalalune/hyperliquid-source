# RE-001: node #115 lazy-materialize predicate 0x5f77190

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what decides a match in the
two-phase filtered accumulation scan 0x5f77330 (PR #2362) — the scan's
predicate was explicitly left unclaimed there, and this item pins it:
which elements the predicate reports as matches, what it writes to
them, and when it never reports the same element twice.

## Windows

* Predicate 0x5f77190..0x5f77326 (406 bytes, FDE range as shown in
  frames.txt). The whole window is the item: the 370-byte body
  (0x5f77190..0x5f77302) plus the three 12-byte landing-pad stubs at
  0x5f77302, 0x5f7730e and 0x5f7731a, which sit inside the FDE range
  but are not predicate instructions — each jumps to a shared resume
  path below the predicate, and no predicate behavior is claimed
  for them.

The window is bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

## Semantics, stated literally

The predicate takes (obj, element) and returns 1 for a match, 0
otherwise. The scan tests the returned byte and skips the element
on zero, so a return of 1 is exactly what makes the scan
accumulate that element (in phase 1) or re-accumulate it (in
phase 2).

* Cached arm: the flag byte at element + 0xb5 is nonzero. Return 0
  at once. No oracle call, no other field read, no mutation. An
  element that was already attempted never matches again.
* Present arm: the flag is zero but the qword at element + 0x78
  is nonzero. Return 0 at once, flag left at zero, no oracle call.
  A later call retries the init.
* Attempt arm: the flag is zero and element + 0x78 is zero. Call
  the materializer oracle 0x5f76a00 (output struct, obj, element,
  0). The oracle writes a status byte and, on success, a result
  object pointer plus two buffers; the oracle's own semantics are
  NOT claimed — the model takes it as a callable returning
  (status_byte, result or None). The flag is set to 1 BEFORE the
  status byte is read, so every attempt — success, error, or
  null result — marks the element attempted.
  * Error path (status nonzero): report through callee 0x5fcf060
    with code 3, the target at [obj + 0x1020] + 0xd0 + 0x30, the
    element's + 0x08 field masked with 0x3fffffffffffffff, and
    the oracle's message string. Only the call itself is
    recorded; what the report writes to the target is NOT
    claimed. The oracle's buffers are freed; return 0.
  * Null-result path (status zero, result pointer null): the
    buffers are freed; return 0. The flag stays 1, so the element
    never matches on a later call either.
  * Success path (status zero, result pointer non-null): copy
    result + 0x58 to element + 0x80, result + 0x68 to
    element + 0x88, result + 0x48 to element + 0x98, result + 0x40
    to element + 0x90, result + 0x78 to element + 0xa0; free the
    buffers; return 1.

Composition with PR #2362: because the flag is set on the first
attempt and the cached arm returns 0, the scan accumulates each
element at most once across both phases — the first phase-1
attempt that succeeds is the element's only accumulation, and a
phase-2 revisit of the same element always skips it.

## What is NOT claimed

* The oracle 0x5f76a00's semantics (what makes it succeed, fail,
  or return a null result).
* The error-report callee 0x5fcf060's effect on its target.
* Any meaning for the element fields beyond the offsets read and
  written here, or for the copied result fields beyond their
  offsets.
* The landing-pad stubs' resume behavior.

## Evidence notes

* Instruction-level detail lives only in the raw disassembly
  excerpt main.txt, kept verbatim and whole-function. The JSON in
  this packet holds semantic records only — no per-instruction
  list. Mnemonics such as `endbr64` in the excerpt are genuine
  instructions present in the target binary, not placeholders:
  verify.py regenerates the excerpt from a fresh objdump run and
  checks it byte-for-byte, and spot-checks gate instructions
  against both a fresh objdump run and the raw binary.
* The objdump command that produced main.txt is recorded in
  export_excerpts.py in this packet; run it from the repository
  root to regenerate the excerpt.

## Verification

Checker ALL CHECKS PASSED (digest, provenance, manifest, excerpt
regeneration byte-for-byte from a fresh objdump run, gate
instructions byte-for-byte vs fresh objdump and raw binary, FDE
range, census, model tests); 11 model checks pass (cached arm,
present arm with retry, full five-field success copy, null-result
attempt marking, error report with code and masked field, second
call after success, second call after error, 62-bit mask,
missing-field guards, packet checks). make doctor exits 1 on
missing providers here (pre-existing); make verify/test/
catalogue-check fail on the LFS-pointer artifact here
(pre-existing, stated honestly in the PR body).
