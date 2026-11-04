# RE-014: validate node #94's probe-gated lookup against node #115

- Component: node #115 probe-gated lookup, cross-release validation of
  the merged #94 packet `research/work-items/RE-001-probe-gated-lookup-94/`
  (PR #2009, commit 96d4e907). That packet was removed from the tree
  by the node 115-only migration (upstream 8fd8db68); the comparison
  here was performed against the packet as merged and against the
  #94 binary bytes, and this item follows the migration's RE-014
  queue row: "Validate a bounded reusable implementation against
  #115; preserve mismatches and do not inherit old addresses".
- Target: node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json). The local copy used here is
  `work/hl-node-115.bin` (git-ignored); its digest was verified before
  analysis and is re-checked by verify.py. The #115 binary was obtained
  through the repository's own Git LFS endpoint, since this VM has no
  git-lfs; the downloaded bytes hash exactly to the provenance digest.
- Bounded question: does node #115 contain the same probe-gated lookup
  behavior that the #94 packet pins at 0x516ca20, and where does it
  differ?
- Answer: yes, end to end, with one correction to the #94 packet's
  shorthand (below). The #115 window is `0x5f0d050..0x5f0d704`
  (1716 bytes, the same size as #94's window), FDE at .eh_frame offset
  0x745904, length 0x38, CIE 0x730230, augmentation field
  `04` + `40 82 02 ff` (pcrel sdata4, decodes to LSDA 0x414a2d).
  The LSDA bytes at 0x414a2d begin `ff ff 01 2a d3 01 16 00 00`;
  the call-site table 9 bytes in begins with the entry
  (start 0x163, length 5, landing pad 0x690, action 0), which matches
  the thunk call at 0x5f0d1b3 (offset 0x163, 5-byte call) and the
  first landing pad at 0x5f0d6e0 (offset 0x690). The full LSDA header
  parse is left as observed bytes; the address and the first entry
  are verified. Landing pads: 0x5f0d6e0, 0x5f0d6ec, 0x5f0d6f8.

## The validated flow, end to end

1. Gate: host +0xc18 null returns 0 at once (0x5f0d0e5..0x5f0d0ef),
   nothing else done.
2. Member resolution: thunk 0x5f0b050 (35 bytes, same size as #94's
   thunk) returns null unless options +0x35 == 0 AND host +0xa60 == 0,
   else tail-jumps to the sharded access 0x5f0a9c0 (by contract).
   A null member skips key handling.
3. Key slice: range start..end-8 (8-byte trailer stripped). Transform
   0x5f32900 (266 bytes, by contract) max-updates the stack-arg-0x18
   output only when larger; when the r8 string argument is non-null,
   the string is replaced wholesale via _M_replace with the pair at
   member+0x68 table +0x30 + ((member+0x90 - (table+0x18)) / 8) * 16.
4. Probe filter: host +0xc60 null skips the probe and calls the
   driver directly. Probe slice: range start, length
   (end - start - 8) - (host +0x10 object) +0x28. Host +0x30 byte zero
   takes the virtual variant (host +0xc58 object +0xa0 predicate on
   the slice struct; false calls the driver directly; true calls the
   +0x98 transform virtual and hashes its (pointer, length) result);
   nonzero takes the direct-hash variant (hash of range start and
   probe length). Hash: 0x61c34a0, seed 0xbc9f1d34.
5. Probe loop, identical to #94's: base = (count * hash32) >> 32,
   words at table +0x8, count at table +0x0, rounds at table +0x4,
   two-bit mask of hash32 * 0x9e3779b97f4a7c13 (bits (prod & 63) and
   ((prod >> 6) & 63)), ror 12 after each passing round, round 0
   always tested even when rounds is 0 (rounds tested = max(rounds, 1)).
6. Hit: perf +0x200 counter, driver 0x5f0ce10 (503 bytes, by
   contract) called with 14 arguments; after return, the -0x82 byte
   is the return value and the -0x81 byte gates the status install.
   Miss: perf +0x208 counter, the literal qword 0x00ffffffffffffff
   stored to the stack-arg-0x20 output slot, and the status-6
   install when the r9 flag byte says so.
7. Status install: record {06 00 00 00 00 00, null pointer} moved by
   0x5f05310 (105 bytes) into the r9 object; skipped when the r9
   first byte is already 2; the caller's post-move delete[] of the
   temporary is dead because the move zeroes it.
8. Epilogue: perf +0x120 counter, return value = -0x82 byte,
   non-null member released via its +0x8 virtual, timer record
   destroyed by 0x5f05950 (91 bytes) when its start value is nonzero.
   Perf prologue: perf_level GLOB_DAT slot 0x64ed2b0 tested; TLS
   counter block at TLS-0x350 + 0x118; TLS byte above 2 installs the
   timer record, above 1 enables the counters.

## The one correction

The #94 packet describes the miss output as "writes -1". The literal
bytes on BOTH binaries store the qword 0x00ffffffffffffff
(`movabs $0xffffffffffffff` at #94 0x516cd90 and #115 0x5f0d3c0,
followed by a full 8-byte store). That is not -1 as a 64-bit value.
The consumer width that would read the slot as -1 is unresolved;
this packet records the literal and flags the shorthand, on both
releases. Everything else in the #94 packet's flow description
matches #115 field for field (see records.json match/drift table).

## Hash byte-identity

The #115 hash 0x61c34a0..0x61c3525 (133 bytes) is byte-for-byte
identical to #94's 0x5422e70..0x5422ef5 (SHA-256 prefix
3ebe23ed28ea5132 for both 133-byte bodies). Semantics, read from
the #115 bytes themselves: eax = length * 0xc6a4a793 XOR seed; per
4-byte word: add the word, multiply by 0xc6a4a793, xor with
(value >> 16); tail bytes added with shifts 0/8/16, final multiply
by 0xc6a4a793, xor with (value >> 24). Empty input returns the seed.
The hash has 26 direct callers in #115, 9 of them with the probe
seed 0xbc9f1d34 as the immediately preceding instruction.

## Census and relocations

Window 0x5f0d050: 9 direct calls, each confirmed as a real call
instruction in objdump output (0x5d614ad, 0x5d61da6, 0x5d7965c,
0x5e707bb, 0x5e7ce72, 0x5eccaa0, 0x5ecd287, 0x5f12b4e, 0x5f12c91);
0 tail jumps, 0 whole-file qword hits, 0 RELATIVE slots. Other
scan counts (census.py): hash 26 calls, thunk 11, driver 2 (this
window and the batch-lookup counterpart at 0x5f0dd88), transform 4,
move 19, timer 10. The window's only RIP-relative data reference is
the perf_level GLOB_DAT slot 0x64ed2b0 (see relocations.txt).

## Claim status

Observation for the window bounds, gate, thunk guard, slice
arithmetic, probe loop math, driver call shape and out-flag
protocol, miss literal, status install, epilogue order, perf
counters, census and hash byte-identity; inference for the names
"host", "member", "probe table" and "driver" (roles, not class
names); unresolved for driver internals, transform internals,
sharded access 0x5f0a9c0 internals, the consumer width of the miss
output slot, and the full LSDA header parse. No component
acceptance gate is marked complete by this packet. The driver and
transform are cited by contract only, not re-mapped; the #94
driver's mapping is PR #2017 (open) and is not re-claimed here.

## Note on evidence text

The raw disassembly excerpts are verbatim objdump output.
Instruction mnemonics appearing in them (including `endbr64` at
each window entry) are genuine instructions present in the target
binary, not placeholders; the packet checker re-verifies sampled
instructions byte-for-byte against a fresh objdump run and the raw
binary. The packet JSON holds semantic records only — no
per-instruction mnemonic list — and the packet carries its own
runnable verify script plus the excerpt generator and census
script, so the checker behind "ALL CHECKS PASSED" is visible in
the diff.

## Reproduction

objdump commands are recorded in export_excerpts.py; run it from
the repository root to regenerate every excerpt. Census method is
recorded in census.py. verify.py re-checks the digest, the
manifest, excerpt regeneration, sampled and self-check instructions
against fresh objdump output and the raw binary, the FDE lines,
and the census counts.
