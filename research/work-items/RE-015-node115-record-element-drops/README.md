# RE-015 — node 115 record element drops: the last readers of the assembled 0x40-byte records

Question: what do the two element drops that destroy the
assembled 0x40-byte records actually do per record? The
assembled-record readers packet (#2559) traced every destroy
path of the records to these drops but left the drops themselves
unopened — its Boundaries section reads: "Hash-pinned, not
traced: … the element drops `0x1538ec0` / `0x474dcd0` (258 B
each), the pair tail helper `0x15ad260` (244 B), …". The
second-structure readers packet (#2506) had asked for "the final
disposition of the extracted words"; #2559 answered it at the
path level, and the disposition itself is performed inside these
two bodies — in particular for the taken entries' words sitting
at the records' +0x30/+0x38 slots. This packet opens both drops:
which record fields each one loads, in what order, through which
slots and callees, how the two instances relate, who calls them,
and what their landing pads redo. (The recorded next question of
#2559 — the merge delegate's later phases — is the
merge-delegate packet's, #2615, and is not touched here.)

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| vec-A element drop | `0x1538ec0..0x1538fc2` | 258 | `7e210dddf72e2ea2174d3e9ab9f5e285c76d2dedee2762fa42b3aaea7d41033d` |
| reader element drop | `0x474dcd0..0x474ddd2` | 258 | `1eb9998a3ae04a9d04b65c94b6152313072624627f05778250ee744c157d068e` |

Both bodies are retained in full. The two callers (pair drop,
exit reader) are #2559 owners, retained here as hash-pinned
boundary context together with the four sub-vector drain
callees the drops call.

## Trace

### Stage 1 — where the drops sit (call census)

A direct-call census over the whole `.text` (sites attributed by
containing FDE) closes the caller set. The vec-A drop
`0x1538ec0` has exactly two call sites, both in the pair drop
`0x15ac5f0`: its main element loop (`0x15ac61d`, stepping 0x40
over the first vector's buffer) and its landing-pad loop
(`0x15ac73d`), which re-walks the remaining elements before the
buffer free and the pair tail helper call. The reader drop
`0x474dcd0` has eight call sites in four functions of the
delegate module: `0x4740dd0` (`0x4740dfd`, `0x4740e4d`),
`0x4747dc0` (`0x4747ded`, `0x4747f0d`), `0x47481c0` (`0x47481ed`,
`0x474823d`) and the exit reader `0x4749ab0` (`0x4749b6d` in the
discriminant arm, `0x4749d2c` in its cleanup). The three sibling
callers are recorded by FDE range only. No other direct caller
of either drop exists in the binary; neither drop is reached
through a descriptor — both are plain direct calls, unlike the
tagged pairs they consume.

### Stage 2 — what one drop does to one record

Both bodies consume the record (argument in `rdi`, kept in
`rbx`) in the same order; site pairs below are vec-A / reader.

1. **The buffer pair.** The word at +0x0 is loaded as a size
   (`0x1538ecb` / `0x474dcdb`); if it is non-zero, the pointer at
   +0x8 (`0x1538ed3` / `0x474dce3`) is freed through the dealloc
   slot `0x64df4a0` (RELATIVE, target `0x635de30`) with that size
   and align 0.
2. **The tagged pair — the taken words' disposition.** Data at
   +0x30 and descriptor at +0x38 are loaded (`0x1538edf` /
   `0x1538ee3`). Descriptor word 0 is called on the data when
   non-null (`0x1538ef3` / `0x474dd03`); then the data is freed
   through the dealloc slot with the size class computed from
   descriptor words +0x8 (size) and +0x10 (align) by the
   tzcnt/cmova idiom (`0x1538f04` / `0x474dd14`), gated on the
   size word. This is the same descriptor protocol the consumer
   uses for the taken pairs directly (the tagged destroys of
   #2559) — here applied to the pair after it travelled inside
   the record.
3. **The sub-vector at +0x18.** A drain callee is called on
   `element+0x18` (normal path: `0x153deb0` / `0x474e8a0`); then
   the header word at +0x18 is loaded and, if non-zero, the
   buffer at +0x20 is freed through the dealloc slot at
   word × 0x10 bytes (`shl 4` at `0x1538f39` / `0x474dd49`) as a
   tail jump — so the sub-vector's elements are 0x10 bytes and
   its header starts with the word the free sizes by.

The record words at **+0x10 and +0x28 are never loaded** in
either body: an element field census over both dumps finds the
+0x0 word loaded once at entry (through `rdi`) and `rbx`
displacements of exactly +0x8, +0x18, +0x20, +0x30, +0x38.

### Stage 3 — the two instances are one implementation

The bodies are clones at the pinned instruction shape. Decoded
instruction offsets are identical (80 instructions), and after
masking the address-dependent tails of branch and slot
instructions the byte streams are byte-identical. All nine
unmasked differences are address encodings: six RIP-relative
displacements to the same two slots (the dealloc slot
`0x64df4a0` five times per body, the cleanup slot `0x64df4c0`
once), the rel32 to the same `_Unwind_Resume` PLT entry
`0x63f0a50`, and the two drain-callee rel32s — the normal drain
(`0x153deb0` vs `0x474e8a0`) and the unwind drain (`0x1539990`
vs `0x474e270`). The bodies' own hashes differ (owners table);
identity is claimed at the masked instruction shape only, the
same standard #2559 applied to its tagged-destroy pair. Note the
pairing this creates: each drop instance is bound to its own
module's drain pair, exactly as the tagged destroys were bound
to their call sites.

### Stage 4 — the unwind shape

Each body carries the same two landing pads. The first
(`0x1538f5c` / `0x474dd6c`) saves the exception, re-runs the
tagged pair's descriptor free with the same tzcnt size-class
idiom, drains the sub-vector through the *alternate* drain
callee (`0x1539990` / `0x474e270`, on `element+0x18`) and falls
into the resume. The second (`0x1538f99` / `0x474dda9`) first
calls through the cleanup slot `0x64df4c0` (RELATIVE, target
`0x1680cab`), then frees the sub-vector buffer (header word at
+0x18, buffer at +0x20, size word × 0x10) through the dealloc
slot, and resumes through `_Unwind_Resume`. Neither pad touches
the +0x0/+0x8 buffer pair; the tagged pair's drop word is not
re-called beyond the first pad's descriptor free.

## Boundaries

Hash-pinned, not traced: the pair drop `0x15ac5f0` and the exit
reader `0x4749ab0` (#2559 owners, context only), the four
sub-vector drain callees — normal `0x153deb0` (235 B) /
`0x474e8a0` (235 B), unwind `0x1539990` (86 B) / `0x474e270`
(86 B) — the dealloc target `0x635de30`, the cleanup target
`0x1680cab`, and `_Unwind_Resume`. What the drain callees do per
0x10-byte sub-vector element, what the record words at +0x10 and
+0x28 hold (never loaded here), and any semantic name for the
record type are not claimed. The three sibling callers of the
reader drop are recorded by FDE range only. No captured code
executed, no runtime value or reconstruction gate is claimed.

## Next question

What do the four sub-vector drain callees do per 0x10-byte
element of the record's +0x18 sub-vector — and are the two drain
pairs (normal `0x153deb0` / `0x474e8a0`, 235 bytes each; unwind
`0x1539990` / `0x474e270`, 86 bytes each) also shape-identical
clones of one another, as their matching sizes suggest?

## Reproduce

```sh
python3 tools/record_element_drops_static.py \
  --binary artifacts/node/115/hl-node \
  --output research/work-items/RE-015-node115-record-element-drops
python3 -m unittest tests.test_record_element_drops_static
```
