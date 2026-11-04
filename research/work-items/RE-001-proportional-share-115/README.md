# RE-001: map node #115 proportional share 0x5f6ad70

## Bounded question

What does the 350-byte leaf function at 0x5f6ad70 compute from its single
object argument, and where is it consumed? PR #2215 left exactly this
function unread: its composite getter calls it once (call site 0x5eeb5b3)
and adds the return into its base sum, with the internals recorded as an
unknown. This packet closes that unknown.

## Window

- Function: 0x5f6ad70..0x5f6aece (350 bytes), FDE at .eh_frame offset
  0x35dcec, length 0x10, CIE 0, no LSDA.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Sole consumer: the composite getter 0x5eeb570..0x5eeb608 (mapped by
  PR #2215), call site 0x5eeb5b3, passing its object (inner + 0x30 + 0x40).
  No other direct call, tail jump, qword reference, or RELATIVE
  relocation to this window exists in the whole binary (see census.py).

## Semantics (literal)

Object fields: total at +0xfc0, hi at +0xfb0, lo at +0xfb8 (all unsigned
64-bit), count as a signed 32-bit at +0x10, entries pointer at +0xa98.

1. total == 0 returns 0. lo >= hi (unsigned) returns 0. Otherwise
   span = hi - lo.
2. count <= 0 returns span with no loop.
3. Otherwise sum the entries: exactly count 24-byte entries, each
   contributing (qword at +0x08 minus qword at +0x00) arithmetic-shifted
   right by 3, accumulated in wrapping 64-bit arithmetic. Entry +0x10 is
   never read.
4. total >= sum (unsigned) returns span.
5. Otherwise return the unsigned 64-bit truncation of
   (double)span * (double)sum / (double)total. Unsigned-to-double
   conversions round to nearest even (the binary's shr/or/addsd path).
   The double-to-unsigned conversion follows the binary's
   comisd/subsd/cvttsd2si/btc path against the constant 2**63 stored at
   0x459360: values at or above 2**63 subtract 2**63 first, then set bit
   63; values at or above 2**64 convert to 0 via the integer indefinite.

## Evidence notes

- The packet's JSON (records.json) holds semantic records only. All
  instruction-level detail lives in the whole-function verbatim excerpt
  function_0x5f6ad70.txt, produced by running, from the repository root:
  `objdump -d --start-address=0x5f6ad70 --stop-address=0x5f6aece work/hl-node-115.bin`
  (see export_excerpts.py; running objdump from the repo root with the
  canonical relative path keeps the header byte-identical).
- Mnemonics such as `endbr64` in the excerpt are genuine instructions
  present in the target binary, not placeholders: verify.py checks sampled
  instruction bytes against the raw binary, and the excerpt regenerates
  byte-for-byte from a fresh objdump run.
- The window makes no calls, has no PLT/GOT use, no stack canary, and no
  rip-relative reference other than the 2**63 constant load.

## Model and tests

- tools/proportional_share_115.py implements the semantics above.
- tests/test_proportional_share_115.py covers the early-zero arms, the
  span arms, proportional truncation, arithmetic-shift and wrapping-sum
  behavior, both 2**63 conversion arms, unsigned double rounding, and
  the packet records.

## Unknowns

- The domain meaning of total, hi, lo, and the entry pairs is not claimed;
  only the arithmetic is.
- Indirect-branch callers, if any, are not covered by the census, which
  spans direct calls, tail jumps, qword references, and RELATIVE
  relocations only.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so no Rust
reconstruction is claimed. `make doctor` fails on missing providers
(pre-existing); the packet's checks are the Python verify script and the
plain-python3 model test run, as stated in the PR body.
