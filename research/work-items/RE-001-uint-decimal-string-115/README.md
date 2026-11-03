# RE-001: map node #115 unsigned-integer decimal string conversion 0x5d4f970

Task ID: RE-001. Bounded question: what does the whole routine at
0x5d4f970 in the node #115 binary do, end to end, as a complete
behavior — not a lone window?

## Evidence and binding

- Target: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching the `artifacts/node/115/hl-node` entry in
  `provenance/artifacts.json`.
- Excerpts: `main.txt` is the whole routine body, produced verbatim by
  `objdump -d --start-address=0x5d4f970 --stop-address=0x5d4fcdd
  work/hl-node-115.bin` (FDE range 0x5d4f970..0x5d4fcdd, 877 bytes).
  The FDE range ends exactly where the next function starts, so there
  is no trailing padding block to excerpt. `export_excerpts.py`
  regenerates the file.
- Instruction-level detail lives only in that verbatim excerpt text
  file. `records.json` holds semantic records only — no
  per-instruction mnemonic list. Mnemonics such as `endbr64` in the
  excerpt are genuine instructions present in the target binary, not
  placeholders; verify.py checks every excerpt instruction
  byte-for-byte against the raw binary.
- Frames: `frames.txt` carries the FDE lines for the routine and its
  nine distinct external caller functions.
- Census: `census.py` scans the executable LOAD segment exhaustively
  for E8/E9 sites targeting this routine and confirms each candidate
  with objdump; `callers.tsv` records the result. The routine has
  exactly 17 direct calls, 0 tail jumps, 0 stored qwords, 0 RELATIVE
  addends.
- Verification: `verify.py` re-checks the digest, the provenance
  entry, the manifest, excerpt regeneration byte-for-byte from a
  fresh objdump run, every excerpt instruction byte-for-byte against
  the raw binary, the FDE ranges, the empty relocation set, census
  consistency including per-site caller-function checks, the
  semantic records, the digit-pair table, and the model tests. It
  prints ALL CHECKS PASSED.

## Semantics

The routine writes the decimal representation of one unsigned 64-bit
integer into a string object. The destination string object is at
rdi (pointer +0x00, size +0x08, capacity-or-inline slot +0x10) and
the value is the unsigned integer in rsi. The result has no sign, no
leading zeroes, no separator, and no terminator counted in the size.

1. Digit count. Values up to 9, 99, 999 and 9999 take the 1, 2, 3 and
   4 digit paths directly. Larger values go through a loop that
   divides by 10000 at each step (multiply by the constant
   0x346dc5d63886594b, shift right by 11 — verified to divide
   exactly by 10000) and counts 4 digits per step, with the final
   partial group resolved by unsigned thresholds at 99999, 999999,
   9999999 and 99999999 adding 5, 6 or 7 to the running count. The
   count is the exact number of decimal digits of the value.
2. String construction. The routine sets the string's pointer to its
   own +0x10 inline slot and builds it through the library
   string-construct call with (digit count, 0). The fill below
   overwrites every constructed byte with a decimal digit, so the
   observable content is exactly the digit string.
3. Digit-pair table. Before filling, the routine copies a 200-byte
   table onto the stack from twelve 16-byte constant chunks plus a
   final overlapping 16-byte chunk at stack offset 0xb9. The
   resulting bytes 0..199 are exactly the pairs 00, 01, ..., 99,
   verified byte-for-byte for every pair against the binary's
   constant chunks.
4. Fill from the end. The loop divides the remaining value by 100 at
   each step (multiply by the constant 0x28f5c28f5c28f5c3 with the
   shift-and-correct sequence — verified to divide exactly by 100
   for sampled values including 0, 99, 100, 99999 and 2**64 - 1) and
   writes the two-character pair for the remainder at the last two
   unwritten positions, working backwards. It stops once the value
   before a step is at most 9999. A remainder of 100..9999 then
   writes one more digit pair followed by one single leading digit;
   a remainder of 0..999 writes one single leading digit. The 1-digit
   entry writes its single digit directly and the 2-digit entry
   writes its pair directly, through the same tail blocks.

Net result: for every unsigned 64-bit input, the destination string
holds exactly the decimal digits of that input. The input is unsigned:
every magnitude comparison in the digit-count and fill logic is an
unsigned comparison, and both division steps use unsigned multiplies
and shifts, so a value such as 2**64 - 1 formats as its 20-digit
decimal form, never with a minus sign.

The routine calls no other node routine. Its only calls are the
library string-construct call (three sites) and the stack-check-fail
call (one site, taken only when the stack canary check fails). There
is no landing-pad block inside the FDE range; the stack-check-fail
call is the only abnormal-exit path in the body.

## Distinctness

This routine is distinct from the neighbouring map routines
(0x5d4ed40, 0x5d4f400) and from the tree assign, clone and teardown
family: it takes no tree, node or container argument, keeps no state
between calls, and its only observable effect is the digit string.
It is also distinct from the decimal-group formatters in open PRs
#2301, #2304 and #2306, which format grouped decimal keys with their
own parsers; this routine formats one bare unsigned integer. One
caller function (0x5eee310..0x5eee421, open PR #2304's group sum) is
recorded site-only; the routines do not overlap.

## Not claimed

- What the formatted values denote, or the semantics of any caller
  beyond the call-site addresses and caller FDE ranges.
- Any behavior of the library string-construct call beyond building
  a string of the requested length, which the fill then fully
  overwrites.

## Model and tests

`tools/uint_decimal_string_115.py` models the conversion following
the binary's own structure: the threshold and divide-by-10000 digit
count, then the fill from the end with the digit-pair table.
`tests/test_uint_decimal_string_115.py` checks it against plain
decimal conversion as an oracle (0, single digits, every threshold
boundary 9/10, 99/100, 999/1000, 9999/10000, 99999/100000, 999999,
9999999, 99999999, powers of 10 and 100 up to 10**19, 2**64 - 1,
2**64 - 2, and a sweep of values across every digit length), plus
rejection of negative inputs, inputs above 2**64 - 1, and non-integer
inputs, where the binary's unsigned 64-bit argument cannot express
them.
