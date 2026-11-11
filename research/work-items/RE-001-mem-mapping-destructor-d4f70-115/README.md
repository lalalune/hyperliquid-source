# RE-001: map node #115 guarded mem-mapping release 0x60d4f70 end to end

## Bounded question

The merged destructor-pair packet (#2133,
RE-001-destructor-pair-115) destroys the member object's
arrays of 16-byte pairs through a callee at 0x60d4f70 that
it cited by contract only, and its unknowns list names
"the internals of the element destroy 0x60d4f70" as open.
What does that callee actually do to each pair, and who
calls it across the whole binary? This packet pins the
whole 33-byte body and the full call census: eleven
direct call sites in five containing FDEs, each confirmed
by disassembling its containing FDE from the FDE start.

## Windows

- Release routine: 0x60d4f70..0x60d4f91 (33 bytes), FDE
  at .eh_frame offset 0x36c9ec, length 0x10, CIE 0 (no
  LSDA). The window ends at the `ret` at 0x60d4f90; the
  `nopl` padding at 0x60d4f88..0x60d4f90 is inside the
  FDE and included. The next function at 0x60d4fa0 is a
  different body (a move-assignment neighbour, cited
  here only as a call site) and is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry
  artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x60d4f70 --stop-address=0x60d4f91 work/hl-node-115.bin
```

The excerpt file is that output verbatim, whole-function.
The window starts with `endbr64`; every mnemonic in the
excerpt is genuine objdump output from the target binary,
not a placeholder, and verify.py checks sampled
instructions byte-for-byte against a fresh objdump run
and the raw binary. Instruction-level detail lives only
in the verbatim excerpt; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

Argument: rdi = a pointer to a 16-byte pair (qword at
+0x00 is the mapping pointer, qword at +0x08 is the
mapping length in bytes). Returns void at source level.

```
ptr = [pair + 0x00]
if ptr == 0:
    return                      # length word never read,
                                # no call, rax = 0
length = [pair + 0x08]
tail-jump munmap(ptr, length)   # PLT 0x63f0c00, GOT slot
                                # 0x64ee250, munmap@GLIBC_2.2.5
```

The body writes no memory at all: the pair is not
zeroed, stored into or otherwise modified on either
path. That is observable at the move-assignment call
site (0x60d4fb5), where the caller itself zeroes the
source pair after the release -- the release does not
do it. The body has no stack frame, no stack canary,
no LSDA and no landing pad; munmap's return value
passes through in rax on the non-null path (a
tail-call artifact; every census call site ignores
rax). The pair pointer itself is never null at any
census call site -- callers pass object members or
walking array pointers -- and the body would fault
on a null pair pointer, which is outside its
contract.

Identity, cited as provenance only: the RE-002 vendor
census identifies this FDE as rocksdb::MemMapping's
destructor (librocksdb-sys 0.11.0+8.1.1, published-
crate rebuild match 30/33) -- a {pointer, length}
mapping descriptor whose destructor unmaps a non-null
mapping. The layout and behaviour pinned here rest on
the binary itself, not on that identification.

## Callers (census-complete)

Eleven direct calls, no tail jumps, and no stored
qword or RELATIVE addend anywhere in the file refers
to the window start, so the window is reached only
through these calls:

- 0x605cc30..0x605cf73 (member destroy, mapped by
  merged RE-001-destructor-pair-115): four sites
  (0x605ccc7, 0x605cd07, 0x605cd27, 0x605cee7), each
  in a loop walking an array of pairs at a 0x10-byte
  stride, releasing one pair per element.
- 0x605cfd6..0x605cffb (an unwind cleanup block): one
  site (0x605cfd9) with rdi = r12, a pair pointer held
  across the protected region; the block continues
  with the stack-canary check and _Unwind_Resume, so
  this release runs on an unwind path.
- 0x605d000..0x605d3a1 (arena grow window): one site
  (0x605d08e) with rdi = r12, called unconditionally
  after an optional call to 0x605e830.
- 0x605db40..0x605dcb2 (a destructor-like body whose
  pair-array loops mirror the member destroy's): four
  sites (0x605dba7, 0x605dbd7, 0x605dbf7, 0x605dc87),
  same walking-pointer pattern.
- 0x60d4fa0..0x60d4fdc (the move-assignment
  neighbour): one site (0x60d4fb5), called with the
  destination pair only when destination != source,
  releasing the destination's previously held mapping
  before the neighbour copies the source pair over it
  and zeroes the source.

Site-by-site argument setup lives in records.json and
callers.tsv; the containing bodies other than the
member destroy are cited at their call sites only and
are not pinned by this packet.

## Verification

- Model: tools/mem_mapping_destructor_d4f70_115.py,
  tests in tests/test_mem_mapping_destructor_d4f70_115.py
  (68 checks: the null path's no-call/no-read/result-0
  behaviour across length words, the single munmap
  with the pair's exact two words, the return-value
  pass-through, and byte-for-byte memory preservation
  including the pair itself).
- Differential: differential.py runs the real 33 bytes
  under Unicorn against the model over 61 cases (the
  structured decision space, two page-flush placements
  proving the length word stays unread on the null
  path and nothing past +0x10 is read on the non-null
  path, and 48 random pairs), comparing the munmap
  event log, the return value, the whole window
  byte-for-byte, the callee-saved registers and the
  stack pointer: 61 cases, 0 mismatches.
- verify.py re-checks the binary digest against
  provenance, the packet manifest, the verbatim
  excerpt, sampled instruction bytes, the FDE record,
  the census (recorded and live), all eleven call
  sites' raw bytes, and the model tests.

## Unknowns (stated, not filled in)

- Which class owns each pair array at the call sites,
  beyond the member destroy's 0x8f0-byte member object
  mapped by RE-001-destructor-pair-115 and this
  window's RE-002 identity.
- The owning body of the unwind cleanup block
  0x605cfd6..0x605cffb and of the destructor-like body
  0x605db40..0x605dcb2.
- Whether any caller observes munmap's return value:
  every census call site ignores rax after the call
  (the routine is void at source level).

## Next steps

- The destructor-like body at 0x605db40..0x605dcb2
  (370 bytes, CIE 0) runs the same four pair-array
  loops as the member destroy and is the natural next
  window in this area; pinning it would also name the
  second pair-array owner.
- The move-assignment neighbour 0x60d4fa0..0x60d4fdc
  and the remaining neighbour FDEs at 0x60d4fe0 and
  0x60d5000 complete the MemMapping-area function
  family around this window.
