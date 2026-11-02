# RE-004 verbatim-copy provenance — node #94

## Claim status

**Claimed.** In the four gate-pattern callers trioA, double-gate, trioB and
gate-like, every non-tag-5 (verbatim) copy path reads a 0x20-byte value
whose shape is wider than the decoder's 3-field output: the decoder writes
exactly 3 fields ([out+0x0] tag byte, [out+0x8] object-pointer qword,
[out+0x10] flag byte), and the copy additionally reads the 22 remaining
bytes ([buf+0x1..0x8] and [buf+0x11..0x20]) and installs them into the
destination object. On the four direct verbatim paths those 22 bytes have
no writer anywhere on the path: they are stale stack residue, propagated
into a live object on every non-tag-5 copy.

**Not claimed.** No downstream impact is claimed: whether any later reader
consumes the stale fields of the installed objects is a separate question
(see Next question). No defect, exploitability, or security severity is
claimed. The trioB vtable path is reported route by route, including the
routes whose callee write extent cannot be verified statically; those
routes are not claimed as stale.

## Scope

Included:

- 6 verbatim paths in `verbatim-paths.tsv`: trioA direct, double-gate
  first-decode, double-gate second-decode, trioB direct, trioB vtable,
  gate-like direct.
- 5 trioB vtable routes in `vtable-routes.tsv` (header values 0, 1-zero,
  1-nonzero, 2, 3), dispatched by the jump table at 0x7c3b84.
- 51 slot verdicts in `slot-verdicts.tsv`: decoder-written 15, stale 8,
  path-dependent 2, callee-extent-unverified 18, produced 7,
  unresolved-indirect 1.
- 17 byte segments in `segments.txt` (15 claim segments, 719 bytes;
  2 anchor segments, 20 bytes), each with start..end, length == end -
  start, and SHA-256.
- 6 functions: trioA (402B), double-gate (963B), trioB (1058B), gate-like
  (1162B), decoder-A (812B), decoder-B (812B).
- 2 decoders, 3 output fields each; 5 jump-table entries; 2 RELATIVE
  relocations; 2 runtime-initialized vtable objects.

Excluded:

- The tag == 5 paths (sentinel gate, constructor installs) except where a
  tag == 5 route writes a buffer the second decode later reads
  (double-gate non-match route: header store + constructor-B output).
- The non-match/match install blocks and landing pads themselves (#168's
  subject), the orchestrator 0x4e6fef0 join-block install, downstream
  readers of the installed objects, and destructor paths.
- The #157–#168 subjects (scaling, mul256 helpers, flag consumption,
  difference writers, operand shapes, tag-5 twins, sentinel gates,
  non-rejoin paths, trio constructors, non-match tail bytes) and #1543's
  fixed-eight topic. Those packets are cited as anchors where reused,
  not re-claimed.

## Observations

### The decoder writes exactly 3 fields

Decoder-A (0x4e6f360) and decoder-B (0x4e84500) each write the output
buffer (rbx, the caller's rdi) at exactly three sites, and no other store
in either decoder targets rbx; the remaining stores go to the decoder's
own frame, heap arrays, or the input struct, and no callee receiving rbx
exists (helpers 0x4e8c100, 0x4e8c420 and PLT memcpy do not take the output
buffer). The three sites are byte-identical between the decoders
(segment digest 5c2cbec8… for both 10-byte groups):

- `[rbx+0x8]` object-pointer qword (decoder-A 0x4e6f5cc, decoder-B
  0x4e8476c),
- `[rbx+0x10]` flag byte (decoder-A 0x4e6f5d0, decoder-B 0x4e84770),
- `[rbx]` tag byte 0x5 (decoder-A 0x4e6f5d3, decoder-B 0x4e84773).

The decoder-write segments are anchors previously claimed by #168
(RE-004-nonmatch-install-tail-bytes-94); they are re-cited here, not
re-claimed as new findings.

### Four direct verbatim paths: 22 stale bytes each

On each direct path the caller makes no frame store to the decoder buffer
between the decoder call and the copy, and the copy reads 7 + 15 bytes
outside the decoder's 3 fields, then installs all of it into the
destination object. Copy completion holds on every branch: the
destination-tag checks between the reads and the stores funnel to the
same final stores (double-gate 0x4e85588, trioB-direct 0x4e859ba,
gate-like 0x4e86636, including their free-call detours).

| caller | buffer | decoder call | tag branch | stale slots | destination |
|---|---|---|---|---|---|
| trioA | [rsp+0x0..] | 0x4e6fd5e (A) | 0x4e6fd69 jne 0x4e6fe04 | [0x1..0x8], [0x11..0x20] | [rbx+0x0..0x20] |
| double-gate (1st) | [rsp+0x20..] | 0x4e852c7 (B) | 0x4e852d6 jne 0x4e853e0 | [0x21..0x28], [0x31..0x40] | [rbx+0xb8..0xd8] |
| trioB (direct) | [rsp+0x20..] | 0x4e8570a (B) | 0x4e85718 jne 0x4e857d9 | [0x21..0x28], [0x31..0x40] | [r14+0xb8..0xd0] |
| gate-like | [rsp+0x20..] | 0x4e862ca (B) | 0x4e862d8 jne 0x4e863d7 | [0x21..0x28], [0x31..0x40] | [r14+0xb8..0xd0] |

trioA's copy stores directly ([rbx+0x1], [rbx+0x4], [rbx+0x8], [rbx+0x10],
[rbx+0x11], [rbx+0x18] at 0x4e6fe04..0x4e6fe39, then jmp to the epilogue);
the other three stage the wide reads below the buffer ([rsp+0x0..0x18])
before the final stores. Staging slots live below the buffer and never
alias it.

### Double-gate second decode: path-dependent, not uniformly stale

The second decode (buffer [rsp+0x50..], decoder call 0x4e854d8, tag
branch 0x4e854e7 jne 0x4e854ff) reads the same relative shape
([0x51..0x58], [0x61..0x70] beyond the decoder fields). Its verdict
depends on which route reached the second decode:

- Non-match install route: [0x50..0x58] is the header qword stored at
  0x4e85325 ([rsp+0x50] = 1), and [0x58..0x88] is constructor-B output
  (0x4e81dc0), so [0x61..0x70] (the 0x1e629b pointer tail bytes and the
  [out+0x10] = 1 qword) is produced. All second-decode reads are
  produced on this route.
- Match install route (constructor-B writes only [rsp+0x20..0x50]) and
  header != 4 route (0x4e852ea jne 0x4e85364): no instruction writes
  [rsp+0x50..0x70] before the second decode, so [0x51..0x58] and
  [0x61..0x70] are stale.
- Reachable route set: {non-match install, header != 4, match install}
  x {[rdi+0xb0] > 4} x {difference-fold condition} x {[r14] == 3}
  (0x4e853d5 je 0x4e854ae, 0x4e855ff jmp 0x4e854ae). The landing-pad
  install at 0x4e85631 is an unwind route, not a verbatim route.

### TrioB vtable path: five routes, three verdict classes

The switch at 0x4e857c0 (`lea rcx,[0x7c3b84]`, `movsxd
rax,[rcx+rax*4]`, `add rax,rcx`, `jmp rax`) dispatches on the header
value; the copy at 0x4e85867..0x4e858c3 reads [0x50..0x70] into
[rbx+0x0..0x20] after a vtable call with out = [rsp+0x50] (or [rsp+0x70]
on the header-1-nonzero route, reassembled at 0x4e85a37).

- Header 0 (entry 0x7c3b84 -> 0x4e8596d): callee is [r14+0x8]
  (indirect). Header 2 (entry 0x7c3b8c -> 0x4e857d0) and header 3 (entry
  0x7c3b90 -> 0x4e8584a): callees come from .got slots 0x57732a8 and
  0x57732b0. Both slots resolve by R_X86_64_RELATIVE relocation to
  .data objects (0x5786858, 0x5786838) whose file bytes are (0, 0, 2):
  the first qword is 0 in the file, so the callee is resolved at runtime
  only and its write extent cannot be verified statically. Verdict for
  all slots on these three routes: callee-extent-unverified.
- Header 1, zero sub-route (entry 0x7c3b88 -> 0x4e85903 -> 0x4e85a17):
  no call. The buffer is fully caller-constructed: [0x50..0x58] is the
  0x574f910 pointer, [0x58] is [r14+0x10], and [0x60..0x70] is zeroed:
  the movdqa at 0x4e85a21 zeroes [rsp+0x20..0x30] (including the first
  decode's pointer slot [0x28]), so the assembly's later reads of
  [0x20] and [0x28] at 0x4e85a3d/0x4e85a47 both yield 0, giving
  [0x60] = 0 and [0x68] = 0. Verdict: fully produced (all caller-made,
  none decoder-made).
- Header 1, nonzero sub-route (entry 0x7c3b88 -> 0x4e85903 -> 0x4e8592d):
  vtable call [r14+0x8] with out = [rsp+0x70]; assembly at 0x4e85a37
  copies [0x70..0x80] to [0x50..0x60], sets [0x60] = r15 =
  [r14+0x30], and sets [0x68] = [0x88]. [0x50..0x68] is produced
  conditional on the callee writing at least 0x10 bytes; [0x68] requires
  the callee to write at least 0x18 bytes past [0x70], which cannot be
  established statically. Verdict: [0x68] unresolved-indirect, rest
  produced-conditional.
- Header 4's table entry (0x7c3b94 -> 0x4e85a56, a panic/cleanup block)
  is unreachable from this switch: header == 4 takes the
  sentinel-compare route, and the switch is reached only with header in
  {0, 1, 2, 3} (header != 4, or post-non-match header = 1).

## Inferences

- The verbatim-copy shape is a property of the callers, not of the
  decoder: all four direct paths copy the same 0x20-byte layout with
  the same 22-byte overhang, while the decoder's contract is 3 fields.
  Any caller that verbatim-copies a decoder buffer without first
  filling it propagates whatever the stack held in the overhang.
- The double-gate second decode shows the overhang is sometimes
  genuinely produced (non-match route), so "verbatim copy reads stale
  bytes" is a per-path verdict, not a blanket property of the shape.
- The trioB vtable path shows the same shape with a different producer
  (a virtual call instead of the decoder). Where the callee is
  runtime-resolved, the shape alone says nothing about provenance;
  only the header-1-zero route, where the caller builds the buffer
  itself, is fully produced.

## Limitations

- TrioB vtable routes header 0, 2, 3: the callee cannot be identified
  statically (indirect [r14+0x8]; .got slots pointing at
  runtime-initialized .data objects). Their slot verdicts are
  callee-extent-unverified, not stale and not produced.
- TrioB vtable route header-1-nonzero: [0x68] (from [0x88]) is
  unresolved-indirect. Identifying the [r14+0x8] callee family would
  settle it; no callee is speculated here.
- Segment-claim overlap with prior packets is zero: no claimed segment
  byte is shared with #157–#168 except the 2 decoder-write anchor
  segments (20 bytes), which are #168's claim re-cited with attribution.
  The trioA/double-gate/trioB blocks sit inside FDEs that #165
  census-listed, but none of #165's 47 gate instruction addresses falls
  inside any segment claimed here; gate instructions themselves are
  #165's claim, cited not re-claimed. Gate-like's blocks are outside
  #165's windows entirely.
- This packet covers the verbatim-copy paths of the four gate-pattern
  callers only. The orchestrator 0x4e6fef0 join-block install, the
  tag == 5 installs, and all other callers of the decoders are out of
  scope; their buffers may or may not show the same shape.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Disassembly addresses are the addresses objdump prints for this
artifact. File bytes for a code address A live at file offset A -
0x1000 (verified: offset 0x4e6ed50 holds trioA's prologue bytes
`55 41 56 53`, matching objdump at 0x4e6fd50; jump-table entries read
from .rodata at their own VAs resolve exactly to the analyzed blocks).
.rodata reads use file offset == VA; .got uses VA - 0x2000; .data uses
VA - 0x3000. Section headers alone do not explain the code addresses;
the mapping above is the empirically verified one, and the generator
fails loudly if any digest, jump-table entry, relocation, or vtable
object check disagrees with the node bytes.

```sh
# trioA verbatim block
objdump -d -M intel --start-address=0x4e6fe04 --stop-address=0x4e6fe39 \
  artifacts/node/94/hl-node
# double-gate first-decode verbatim reads and final stores
objdump -d -M intel --start-address=0x4e853e0 --stop-address=0x4e8540e \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e85588 --stop-address=0x4e855ca \
  artifacts/node/94/hl-node
# trioB switch and vtable copy
objdump -d -M intel --start-address=0x4e857c0 --stop-address=0x4e858c3 \
  artifacts/node/94/hl-node
# gate-like verbatim reads and final stores
objdump -d -M intel --start-address=0x4e863d7 --stop-address=0x4e86405 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e86636 --stop-address=0x4e86678 \
  artifacts/node/94/hl-node
# decoder 3-field writes (both decoders, byte-identical)
objdump -d -M intel --start-address=0x4e6f5cc --stop-address=0x4e6f5d6 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e8476c --stop-address=0x4e84776 \
  artifacts/node/94/hl-node
# jump table and relocations
python3 -c "import struct; d = open('artifacts/node/94/hl-node','rb').read(); \
  print([hex(0x7c3b84 + struct.unpack('<i', d[0x7c3b84+4*i:0x7c3b88+4*i])[0]) \
  for i in range(5)])"
readelf -r -W artifacts/node/94/hl-node | grep -E '57732a8|57732b0'
```

Deterministic regeneration (the generator writes only to --out):

```sh
python3 tools/verbatim_copy_provenance.py \
  --out research/work-items/RE-004-verbatim-copy-provenance-94
```

Re-running the generator into a second directory with different
PYTHONHASHSEED and TZ produces byte-identical evidence.json,
verbatim-paths.tsv, vtable-routes.tsv, slot-verdicts.tsv and
segments.txt; README.md and MANIFEST.sha256 are not generator outputs
and are excluded from that diff.

## Next question

- Do downstream readers consume the stale fields ([obj+0x1..0x8],
  [obj+0x11..0x20]) of the objects installed by the four direct verbatim
  paths? A reader census over the destination objects ([rbx+0x0..0x20]
  in trioA, [rbx+0xb8..0xd8] in double-gate, [r14+0xb8..0xd0] in trioB
  and gate-like) would decide whether the propagated residue is
  observable or merely installed.
- Which runtime initializer fills the .data objects 0x5786838 and
  0x5786858 (and what the [r14+0x8] callee family writes)? Settling
  either would resolve the trioB vtable header-0/2/3 extents and the
  header-1-nonzero [0x68] slot.
