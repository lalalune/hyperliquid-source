# RE-010: MessagePack Content value reader, ext visitor and bytes visitor behind the TagOrContent key reader (node #115)

With this packet, the generic MessagePack `deserialize_any` step of node #115 can be rebuilt as code:
how one marker (or the peeked marker) becomes a serde `Content` value. That covers the 225-entry
marker jump table and the 18-entry ext table, every scalar `Content` tag, the length prefixes of
str / bin / ext / array / map, UTF-8 validation with the bytes fallback, the u16 depth budget around
the collectors, the remaining-count check after a collector, the boxed ext `Newtype`, every EOF and
short-payload error form, and the landing pads of all panic and alloc-error sites. These are the
value-reader and visitor callees that the three previous RE-010 packets (key reader, map / seq
visitors, tagged visitor) left as contract stubs:

- value reader 0x17fb290 / 0x2f7f5e0 / 0x47d2470 (2,074 B each);
- primitive leaf 0x14b9940 (665 B, shared, run as real code inside the value reader);
- ext visitor 0x21e1930 / 0x3b69ad0 / 0x57afa00 (727 B each);
- bytes visitor 0x21e2670 / 0x57afce0 (413 B each).

The reconstruction is the pure `ModelVR`, `ModelExt` and `ModelBytes` classes in
`tools/re010_content_value_reader_115.py`. The tool runs the original bytes of all 11 bodies plus the
shared leaf over 38,554 cases with the collectors, allocator and drops scripted. The binary is never
executed. The result is 0 mismatches in every copy, and 93/93 wrong models, corrupted images and
out-of-range inputs are rejected.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `0781ce048`. `references/can1357-hl` was not used.
- Claim status:
  - Observation, proved by running the original bytes against the reconstruction: control flow,
    constants, jump-table arms, result bytes, call arguments, cursor / peek / depth write-back, heap
    blocks, LSDA call sites and landing pads.
  - Inference: the serde / rmp_serde names (`deserialize_any`, `ContentVisitor`, `Content` variants,
    `ExtDeserializer`, `SeqDeserializer`, `Marker`).
  - Unresolved: the bodies of the stubbed callees (see scope).
- Scope included: the full bodies of the 11 functions above (every instruction decoded, 478/484,
  165/175 and 108/110 anchor-copy instructions reached; the rest are listed in `coverage.tsv`), their LSDA tables, both jump tables for all
  three value-reader copies, and the shared primitive leaf.
- Scope excluded: the callee bodies, all stubbed by contract: map / seq collectors (already
  reconstructed in `RE-010-content-map-seq-visitors-115`), the allocator, `handle_alloc_error`,
  `RawVec` grow, free, the Content / result drops, `str::from_utf8` (a Python UTF-8 check on the real
  input bytes), and the panic functions. The bytes visitor copy 0x3b68f50 (445 B) has a different
  instruction layout and is not modelled. Other RE-001 packets list some of these addresses only as
  caller rows of a shared callee (`_Unwind_Resume` or a drop); they do not decode the bodies.

## Reproduce

```
python3 tools/re010_content_value_reader_115.py --out research/work-items/RE-010-content-value-reader-115
python3 -m unittest tests.test_re010_content_value_reader_115
cd research/work-items/RE-010-content-value-reader-115 && sha256sum -c MANIFEST.sha256
```

The tool and tests use only the Python 3 standard library and the shared `tools/elf_index.py` and
`tools/fde_extents.py` parsers. They call no external program and never execute the binary. The tool
checks the input SHA-256 first. Generation takes about 55 s and about 380 MB. Two generations produced
byte-identical output: one with `PYTHONHASHSEED=0`, `TZ=UTC`, the other with `PYTHONHASHSEED=12345`,
`TZ=Asia/Seoul`, both with an empty PATH. The 21 tests take about 25 s and none is skipped.

## Evidence

All numbers and tables are produced by the tool from ELF bytes: section headers via `elf_index`, FDE
and LSDA via `fde_extents` and the uleb call-site table, `.rela.dyn` RELATIVE relocations for the GOT
slots, `.rela.plt` for `_Unwind_Resume`, and fixed-pattern instruction decoding.

| file | content |
|---|---|
| `functions.tsv` | per kind and copy: FDE extent, LSDA, instruction and call counts, frame size, static EOF error constant |
| `call_sites.tsv` | every call site of the anchor copy by offset, its role, each copy's target, landing pad and action |
| `lsda.tsv` | the call-site tables (the same in all copies of a kind) |
| `tables.tsv` | both jump tables of the three value-reader copies: index to arm offset |
| `coverage.tsv` | every instruction of the three anchor copies, whether it was reached, taken / not-taken edges |
| `cases.tsv` | a sample of the cases: input, peek slot, depth, collector script, outcome, result bytes, callee sequence, state |
| `mutants.tsv` | 93 negative controls and whether each was detected |
| `summary.json`, `measure.json` | totals and outcome classes |

### Interface (observed)

- Value reader: `rdi` = out `Result<Content, rmp::Error>` (0x28 B: a qword result at +0, `Content` tag at +8,
  payload from +0x10), `rsi` = the deserializer: cursor +0x10, remaining length +0x18, peek flag +0x20
  (1 = no peeked marker, else the marker discriminant), peek data +0x21, depth budget u16 +0x22.
- Collectors get `{ de, left: u32 }` (+0 / +8) on the value reader's frame; the ext visitor gets
  `{ de, len: u32, state: u8 }` (+0 / +8 / +0xc); the bytes visitor gets a slice iterator
  `{ ptr, end, count }`.
- `Content` tags seen: 0 Bool, 1 U8, 2 U16, 3 U32, 4 U64, 5 I8, 6 I16, 7 I32, 8 I64, 9 F32, 0xa F64,
  0xd Str (borrowed), 0xf Bytes (borrowed), 0x12 Unit, 0x13 Newtype(Box), 0x14 Seq, 0x15 Map.

### Behaviour (reconstructed and proved)

- **Peek.** The peek flag is set to "none" on entry, before anything is read. A peeked discriminant goes
  straight to the 225-entry table; only 0 (fixpos), 0x80 (fixmap), 0x90 (fixarray), 0xa0 (fixstr),
  0xc0..0xdf and 0xe0 (negative fixint) are valid. Every other entry is the `ud2` arm.
- **Fresh marker.** With no peek and no input the result is `Err` tag 0 with the static EOF error.
  Bytes below 0x80 and from 0xe0 up go to the primitive leaf as U8 / I8; 0x80..0x9f are fix map / array
  with the low nibble as the count; 0xa0..0xbf are fixstr with the low 5 bits as the length; 0xc0..0xdf
  use the table. 0xc1 is `Err` tag 2 with the marker byte.
- **Scalars.** 0xc0 Unit, 0xc2 / 0xc3 Bool, 0xca..0xd3 floats and integers are built by the shared leaf
  0x14b9940 (big-endian read, payload at +9 / +0xa / +0xc / +0x10 by width). A short read consumes
  the rest of the input and returns `Err` tag 1 with the leaf's own static EOF constant; a one-byte read
  with no input consumes nothing.
- **Strings.** Length prefixes of 1, 2 or 4 bytes; a length longer than the rest returns `Err` tag 1
  with the constant `0x2500000003` and consumes nothing after the prefix. Valid UTF-8 gives Str (0xd) with
  the validator's pointer and length; **invalid UTF-8 gives Bytes (0xf), not an error**. bin8/16/32 give
  Bytes the same way.
- **Collectors and depth.** The depth budget is decremented first. Zero before the decrement panics
  (`panic_sub`, no pad). Zero after it returns `Err` tag 8 and leaves the depth at 0. The collector result
  is copied through a frame slot. An `Err` from a collector is returned **without** restoring the depth.
  After an `Ok`, a remaining count of 0 is accepted; otherwise `Err` tag 4 carries `n - left`
  and the collected `Content` is dropped. `left > n` panics in the subtraction into a drop pad. The ext
  path restores the depth after an `Ok` and after an `Err`.
- **Ext.** ext8/16/32 read a length; fixext 1/2/4/8/16 use 1 << k. An ext EOF writes the marker and the
  low byte of the remaining length (or the data byte for ext8) into the error. The visitor result is
  boxed (`alloc(0x20)`) as Content::Newtype (0x13); an allocation failure calls `handle_alloc_error`
  into a pad that drops the staged value.
- **Ext visitor.** A state byte (0 tag, 1 data, 2 done) drives a two-element Vec: the tag as I8 (5) and the data
  as Bytes (0xf). A short payload returns `Err` tag 1 with `0x2500000003`; any other state returns
  `Err` with the state byte as the tag and marker byte 0xc1. Elements carry register leftovers in the
  fields the variant does not use; the model reproduces them. An Err drops the collected elements in
  order, then frees the buffer.
- **Bytes visitor.** Capacity is `min(end - ptr, 0x8000)` (zero for a null start), allocated as `cap * 32`
  bytes; every byte becomes Content::U8 (1). A counter that is one step from overflowing panics before
  the element that would overflow it, into a pad that drops the Vec.
- **Landing pads.** Only the six panic / alloc-error sites in the value reader have pads (drop the partial
  result, resume); every other stub call in it escapes. A throw inside a pad's drop reaches
  `terminate`. The ext and bytes visitors have pads at the grow, drop and panic sites; the final free in
  the ext visitor is outside every call-site range (`no_call_site`).

## Implementation and comparison

Not yet implemented in Rust. The reconstruction is the pure Python `Model*` classes. The comparison
object per case is (outcome, 0x30 result bytes, ordered callee list with semantic arguments, cursor /
remaining / peek / depth / access state after the call, heap block digests).

| group | cases | mismatches |
|---|---|---|
| value reader x 3 copies (first byte x tails, every peeked discriminant x data x tails, collector / ext scripts, depth, alloc failure, unwinds) | 33,237 | 0 |
| ext visitor x 3 copies (state x length x tails x unwind index) | 4,743 | 0 |
| bytes visitor x 2 copies (lengths, counter near overflow, clamp and grow, unwinds) | 574 | 0 |
| total | 38,554 | 0 |

Negative controls (93, all detected):

- 24 wrong models (15 value reader, 4 ext, 5 bytes): depth off by one, no depth restore, leftover check
  removed, bad UTF-8 as Str, wrong tag for the Newtype, unsigned i8, fixext length doubled, peek not
  consumed, map16 read as a seq, wrong ptr from the validator and others;
- 59 corrupted images: one conditional-jump condition flipped in the anchor copy (41 in the value reader,
  11 in the ext visitor, 7 in the bytes visitor); each changes at least one result;
- 10 out-of-range inputs and boundaries: flipped input digest, a non-FDE start, a wrong size for the kind,
  a wrong anchor, a truncated sweep, an unmapped read, a wrong leaf extent, a discriminant past the
  table, a string longer than the input.

## Results and limitations

- 38,554 cases, 0 mismatches, 93/93 negative controls detected (`measure.json`).
- Instruction coverage of the anchor copies: 478/484 (value reader), 165/175 (ext), 108/110 (bytes). The
  uncovered instructions are listed in `coverage.tsv` (covered = 0): in the value reader the five
  `jmp` instructions after the panic pads and the final `terminate` call; in the ext visitor the pad that
  drops the elements after a failed drop (it needs two collected elements at an Err, which the visitor
  cannot produce: an Err comes at the first or second element) and two `terminate` calls; in the
  bytes visitor the `ud2` after the counter panic and one `terminate` call. The `ud2` arms of the jump
  table are covered by the peeked-discriminant cases.
- Bytes the visitors never write (frame padding in the result) are compared against the Machine's
  stack fill 0x5c; the real stack contents there are not observable statically.
- The primitive leaf is shared: all three value-reader copies call the same body through GOT slot
  0x64dffb0 (RELATIVE to 0x14b9940).
- The map / seq collectors and the drops are stubs; the whole recursion (value reader calling the
  collectors, which call the value reader) is not run as one machine.
- Nothing here claims a component gate. No Rust code is added.

Next question: run the value reader, the map / seq collectors and the drop functions as one machine
(real recursion with an unwinder) so that the stubbed collector results become observed ones.
