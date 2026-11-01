# RE-001: node #94 wrapper-chain dispatch via three slots

Task RE-001, bounded question: how does node #94 resolve a value
through the current object's wrapper chain, and what do the three
near-identical getters at 0x514dfa0, 0x514e030 and 0x514e0c0 return?

## Answer (see records.json for the full semantic record)

One shared head helper plus three getters that differ only in the
dispatch-slot offset and the sentinel cell they compare against:

* `current_head` (0x514df80, 19 bytes): returns
  `[[outer + 0x788] + 0x6b0]` — the current head node, or null.
* Each getter (outer in rdi, out pointer in rsi) first calls the
  helper. A null head returns 0 with `*out` untouched.
* Otherwise the getter walks a chain of wrapper nodes. A wrapper
  holds an inner-object pointer at +0x00 and the next wrapper at
  +0x38. The dispatch slot of a wrapper is
  `[[wrapper + 0x00] + slot_offset]`, where slot_offset is 0x70,
  0x78 or 0x98 depending on the getter.
* The walk compares each visited wrapper's dispatch slot against
  the contents of the getter's sentinel cell (0x5777a28 for the
  0x70 getter, 0x5777a78 for the 0x78 getter, 0x5777a38 for the
  0x98 getter). While the slot equals the sentinel, the walk
  advances to the next wrapper — at most four sentinel nodes are
  skipped. The first non-sentinel slot is called with the wrapper
  as its argument, the result is stored at `*out`, and the getter
  returns 1. The fifth node in the walk is called unconditionally:
  its slot is never compared against the sentinel.
* No PLT calls exist in any of these four functions: every call
  is an indirect `call *register` through a dispatch slot, so
  relocations.txt records that there are no PLT relocations.

Explicit unknowns: what the wrappers, their inner objects and the
dispatched values mean in the wider program (only the walk, the
offsets and the return contract are pinned); what function pointer
the sentinel cells hold at runtime (the model takes the sentinel
as a parameter and compares by identity, exactly as the code
compares against the cell contents); behaviour when the chain has
fewer than five nodes and every slot equals the sentinel (the
code would dereference the null next pointer, so no result is
pinned for that shape); and the reaching path into these getters
(the caller census below found no direct caller claimed here).

## Caller census

A full .text direct-e8 byte scan, a full .text e9 tail-jump scan
and a whole-file qword-pointer scan were run for all four
functions:

* `current_head` (0x514df80) has exactly three direct callers —
  0x514dfa8, 0x514e038 and 0x514e0c8 — which are the entry calls
  of the three getters themselves. No tail jump, no vtable
  pointer.
* Each getter (0x514dfa0, 0x514e030, 0x514e0c0) has zero direct
  callers, zero tail jumps and zero qword pointers anywhere in
  the file.

So the helper's only consumers are the three getters, and the
getters' reaching path is left unclaimed rather than guessed,
as with earlier RE-001 items whose window has no direct caller.

## Evidence notes

Instruction-level detail lives only in the raw disassembly
excerpts in this directory, which are verbatim whole-function
objdump output (each excerpt runs to the next FDE start, so it
includes the int3 padding after the function's FDE end). The
mnemonics in those excerpts — including `endbr64` at each entry —
are genuine instructions present in the target binary, not
placeholders: verify.py regenerates every excerpt byte-for-byte
from a fresh objdump run on the digest-verified binary, and the
pre-submit self-check re-verified three sampled instructions
against a fresh run. The JSON record holds semantic records only,
never a per-instruction mnemonic list.

Excerpt commands (run from the repository root):

    objdump -d --start-address=0x514df80 --stop-address=0x514dfa0 work/hl-node-94.bin
    objdump -d --start-address=0x514dfa0 --stop-address=0x514e030 work/hl-node-94.bin
    objdump -d --start-address=0x514e030 --stop-address=0x514e0c0 work/hl-node-94.bin
    objdump -d --start-address=0x514e0c0 --stop-address=0x514e160 work/hl-node-94.bin

The packet's verify.py and export_excerpts.py are committed in
this directory; run `python3 verify.py` from here to re-check
the packet against the binary.
