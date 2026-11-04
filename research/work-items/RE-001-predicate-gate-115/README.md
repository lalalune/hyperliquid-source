# RE-001: map node #115 predicate gate 0x5f132a0/0x5f132c0

## Bounded question

What does the two-stage predicate at 0x5f132c0 / 0x5f132a0 decide about a
record, and where is it consumed? The windows sit between two already-mapped
clusters of the same object family: the threshold check 0x5f13240 and the
getters at 0x5eeb460..0x5eeb608 (the single-list sums of PR #2215 live at
0x5eeb510 and later). This packet pins the predicate end to end: both
windows whole, the getter that exposes it whole, and all four confirmed
call sites with the branch each takes on the result.

## Windows

- Flag-gated compare: 0x5f132a0..0x5f132ba (26 bytes), FDE at .eh_frame
  offset 0x359118, length 0x10, CIE 0, no LSDA.
- Two-stage gate: 0x5f132c0..0x5f132e5 (37 bytes), FDE at .eh_frame offset
  0x35912c, length 0x10, CIE 0, no LSDA. Its body ends with a direct e9
  tail jump to 0x5f132a0, not a return.
- Getter: 0x5eeb460..0x5eeb488 (40 bytes), FDE at .eh_frame offset
  0x356f2c, length 0x18, CIE 0, no LSDA.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## Semantics (literal)

The record argument R carries: a pointer at +0x08, a signed 32-bit value
at +0x10, a signed 32-bit threshold at +0x04, and a flag byte at +0x15.
The linked record (R+0x08) carries an unsigned 64-bit value at +0x10.

Flag-gated compare (0x5f132a0):

1. flag == 0 always takes the compare arm, whatever the value.
2. flag != 0 and value > 0 (signed) returns the flag byte itself,
   zero-extended -- not normalized to 1.
3. Otherwise (flag != 0 and value <= 0) takes the compare arm.
4. Compare arm: returns 1 when threshold <= value (signed 32-bit
   comparison), else 0.

Two-stage gate (0x5f132c0):

1. It compares the sign-extended value (signed 32-bit at +0x10) with the
   linked record's unsigned 64-bit value at +0x10, as 64-bit values.
2. On mismatch it returns 1 at once.
3. On equality it tail-jumps to 0x5f132a0 with the same record argument
   and returns whatever the flag-gated compare returns.

Getter (0x5eeb460): takes an outer object and an out pointer. It reads
inner = outer + 0x788, calls 0x5f132a0 with inner + 0x8f0, stores the
zero-extended predicate byte to *out, and returns 1 unconditionally. A
flag byte other than 0 or 1 is stored as-is.

## Consumers (all confirmed as real e8 calls from their containing FDEs)

Every consumer passes a record at +0x8f0 of its object and tests the
returned byte immediately:

- 0x5eeb476, inside the getter above: stores the byte, returns 1.
- 0x5e8d1e6, inside 0x5e8d0c0..0x5e8da33: calls the gate 0x5f132c0;
  a nonzero result jumps to 0x5e8d1b0 (the skip path), zero continues
  to the next check.
- 0x5ddafe7, inside 0x5ddae20..0x5ddb1a0: calls 0x5f132a0; a zero result
  jumps away to 0x5ddae67, nonzero proceeds (lock increment and flag
  store follow in the excerpt neighborhood).
- 0x5de860e, inside 0x5de8200..0x5de99e4: calls 0x5f132a0; a zero result
  jumps to 0x5de89e0, nonzero proceeds.

Whole-file census: 3 direct calls to 0x5f132a0, 1 direct call to
0x5f132c0, 1 tail jump (0x5f132c0 -> 0x5f132a0), 0 qword references, 0
RELATIVE relocation addends for either window start (see census.py).

## Evidence notes

- The packet's JSON (records.json) holds semantic records only. All
  instruction-level detail lives in the whole-function verbatim excerpts
  function_0x5f132a0.txt, function_0x5f132c0.txt, and
  function_0x5eeb460.txt, produced by running, from the repository root:
  `objdump -d --start-address=<start> --stop-address=<end> work/hl-node-115.bin`
  (see export_excerpts.py; running objdump from the repo root with the
  canonical relative path keeps the header byte-identical).
- Mnemonics such as `endbr64` in the excerpts are genuine instructions
  present in the target binary, not placeholders: verify.py checks sampled
  instruction bytes against the raw binary, and the excerpts regenerate
  byte-for-byte from a fresh objdump run.
- The three windows make no PLT calls, have no rip-relative references,
  and no stack canaries; the getter's sub rsp,8 is call alignment only.

## Model and tests

- tools/predicate_gate_115.py implements the semantics above, including
  the consumer branch directions.
- tests/test_predicate_gate_115.py covers every arm of both windows, the
  sign-extension equality in the gate, the getter's raw-byte store and
  unconditional 1, the branch direction at each of the four call sites,
  and the packet records.

## Unknowns

- The domain meaning of the record fields is not claimed; only the branch
  arithmetic is.
- Indirect-branch callers, if any, are not covered by the census, which
  spans direct calls, tail jumps, qword references, and RELATIVE
  relocations only.
- The internals of the three large callers are not read; only their call
  sites and the immediately following branches are claimed.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so no Rust
reconstruction is claimed. `make doctor` fails on missing providers
(pre-existing); the packet's checks are the Python verify script and the
plain-python3 model test run, as stated in the PR body.
