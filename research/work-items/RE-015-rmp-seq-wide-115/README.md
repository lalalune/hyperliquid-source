# RE-015: 27 more rmp-serde newtype(Vec<T>) serializers of node #115, six of them with the real MessagePack unsigned writers

This packet makes it possible to rebuild the MessagePack writer of 27 more `newtype(Vec<T>)` fields that the first
sequence packet (`RE-015-rmp-seq-newtype-115`) listed as "other-shape" without testing them: 21 bodies are now covered
by the same executable model (reserved-name reject, u32 length split, direct vs buffered array, element-error
hand-back), and the six stride-8 bodies (`Vec<u64>`-like fields in the three copy families) are covered byte for byte,
because their element writers, the in-binary rmp `write_uint` copies, run for real: smallest-form tag
(`0x00..0x7f`, `0xcc`, `0xcd`, `0xce`, `0xcf`), big-endian payload, the compound counter, the 0x80-byte buffer growth
and the counted copy. The model matched the real bytes on 12,000 generated cases with 0 mismatches, and all 174
negative controls were detected.

- Component ID: `constants` (RE-015 serializer work; same component as the packets this one extends)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: lalalune/hyperliquid-source main `0781ce04826eeefd89fe336cb8ea073be0c1de30`;
  no reference source used (references/can1357-hl was not consulted)
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (rmp-serde names: `serialize_newtype_struct`, `write_uint`, `Compound::end`; the stride-8 element type is a 64-bit
  unsigned integer because the writers accept a u64 value in `rdx`)
- Scope included: the 27 bodies in `bodies.tsv` (21 on recording element stubs, 6 on the real unsigned writers), the
  six real writers `0x25e9f10 0x25e9c70 0x3d51450 0x3d517e0 0x57cfd20 0x57d00b0`, the three copy families' array-header
  writers and `Compound::end` copies as real dependencies. Scope excluded: the 39 other scan members (reasons in
  `scan.tsv`), the two members named in other packets (`0x41a3070`, `0x419d8a0`), the element serializers of the 21
  stub bodies (14 distinct callees, recording stubs), and every claim about the semantic type of the fields. No progress
  gate is requested.
- Dependencies: `tools/re015_rmp_seq_newtype_115.py` (evaluator, model, `body_facts`, family scan) and
  `tools/re015_rmp_vecdeque_u64_115.py` (evaluator copy with the `write_uint` model); both are merged on main.

## Reproduce

From the repository root (Python 3 standard library only; binutils not needed; the binary is never executed):

```
python3 tools/re015_rmp_seq_wide_115.py --out research/work-items/RE-015-rmp-seq-wide-115
python3 -m unittest tests.test_re015_rmp_seq_wide_115
```

- The tool checks the input SHA-256 first (both evaluators) and stops on any other binary.
- It writes `bodies.tsv`, `scan.tsv`, `cases-sample.tsv`, `uint-cases-sample.tsv`, `controls.tsv`,
  `undetected-sites.tsv`, `coverage.tsv`, `summary.json` and `measure.json`.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical files. A run takes a few minutes.
- Case generation is a SHA-512 counter stream keyed by body address; `--per-body` (default 400, stub bodies) and
  `--per-uint` (default 600, real-writer bodies) change the case counts.

## Evidence

All numbers come from `tools/fde_extents.py`, `tools/elf_index.py` and the instruction bytes; nothing is parsed from
objdump or readelf.

### Which members were left out, and why (`scan.tsv`)

The first packet's family scan finds 122 FDEs with the `_ExtStruct` name test and a call to one of the six
`Compound::end` copies. 54 are modelled there, 2 are excluded there, and 66 were listed as "other-shape". For each of
those 66 this tool re-reads the single add/sub stride pair, then applies the first packet's `body_facts` unchanged
(six direct calls in the order header writer, element, element, `Compound::end`, element, compound element; one
stride; the four `.got` calls malloc/handle_alloc_error/sdallocx/count-overflow panic; the 0x80, `0xff0101` and
`1 << 63` constants; the `_ExtStruct` immediates; the "expected tuple" text). Result:

| members | verdict |
| --- | --- |
| 27 | pass `body_facts`; 21 run on stubs, 6 on real writers |
| 25 | no add/sub stride pair at all: other shapes (the 556/658/727 B bodies belong to the VecDeque and BTreeSet packets, the 1,180/2,011/2,120 B bodies have several loops) |
| 6 | a fifth `.got` call `0x64e4d08` (the 979/960 B shape) |
| 6 | element callee does not take `(slot, &element, serializer)`: the recording stub contract check raises on the probe cases (`0x2274420 0x2274a90 0x41a07e0 0x41a44c0 0x52f63a0 0x52f8b90`) |
| 2 | 14 direct calls (`0x419a670`, `0x419c5c0`) |

### The six stride-8 bodies (`bodies.tsv`, `element_kind = uint-real`)

`0x226d4c0 0x226ff00` (family 226, layouts a and b), `0x419dee0 0x41a6360` (419), `0x52f2d00 0x52f81d0` (52f).
Layout a bodies call one `write_uint` copy for every element; layout b bodies call the direct (finish_grow inlined)
copy on the outer serializer and the layout-a copy on the compound. Observed facts, each re-derived by the tool:

- Each body loads one 8-byte element per step and passes it in `rdx` to the writer (`rsi` = serializer or compound),
  which is why the recording stubs cannot run them (the elements need memory).
- Every writer stores its result as `word0 = 2` (Ok) and the used marker (`0xcc..0xcf`) at `slot+8`; no body reads it.
  `undetected-sites.tsv` lists the 21 flip sites that only change that byte; they are not counted as controls.
- Header: `write_array_len(n as u32)`; arrays of 16 to 65,535 use `0xdc`, larger ones `0xdd`.

## Implementation and comparison

`model_b` (in `tools/re015_rmp_seq_wide_115.py`) predicts, for one case, the appended bytes, the 3-word result, the
ordered event list (header length, every writer call with value/serializer kind/compound counter/buffer length/config
word, buffer allocation, reserve calls, release) and the allocation-failure boundary. The comparison runs the real
bytes of the body, header writer, `write_uint` copies and `Compound::end` in the concrete x86-64 evaluator and requires
equal bytes, result record, events and untouched memory. For the 21 stub bodies the first packet's `model` is reused.

Case mix per body: reserved name `_ExtStruct` and one-bit variants, lengths 0..300, wrapped lengths `n >= 2^32` whose
8-byte (or `stride`-byte) walk wraps to a small element count (buffered path), the u32/array-header edges
`0xffff 0x10000 0x10001 0xffffffff 0xfffffff0 0x100000000 0x100000001 2^64-1` with a fault at element 1..3, injected
element/header errors, allocation failure of the 0x80 buffer, random and boundary element values
(`0 0x7f 0x80 0xff 0x100 0xffff 0x10000 0xffffffff 2^32 2^64-1`).

Negative controls (all detected, counted in `measure.json`):

- 125 on the stub bodies: 15 model mutants (array header bounds, u16 header, ext prefix/tag/message length, config
  mask, split at 2^31, iteration count, error tag, buffer release, count + 1, missing copy), 105 one-bit flips of
  the name-length, u32-shift, 0x80-buffer, config-mask and message-length immediates, 5 range controls.
- 43 on the real-writer bodies: 17 model mutants (including the four `write_uint` width limits), 26 one-bit flips of
  width thresholds and tag bytes inside the real writers.
- 6 range controls: a body address that is not an FDE start, wrong stride, wrong layout, wrong copy family, a binary
  with one flipped byte, a first-packet body re-listed as new.

## Results and limitations

| item | value |
| --- | --- |
| bodies newly modelled | 27 (21 stub, 6 real writers) |
| cases | 12,000 (8,400 stub + 3,600 real writers), 0 mismatches |
| negative controls | 174 detected of 174 |
| body instructions executed | 3,964 of 4,554 on the stub bodies (the rest are arms no generated case reaches); the six writers `0x25e9f10 0x3d51450 0x57cfd20` run 240 of 240 instructions |
| flip sites not counted | 21 (the discarded Ok marker byte), listed in `undetected-sites.tsv` |

Ownership note: `0x2273890` and `0x2273f30` occur in the merged `serialization-rmp-newtype-forward-115/bodies.tsv`
only as the `fde_end` of the neighbouring wrapper bodies `0x2273720` and `0x2273dc0` (the next FDE starts there); the
other addresses of this packet occur only in address-inventory lists (`callers.tsv`) of RE-001 packets and, for the
850-byte shape, in the "Next question" of the merged BTreeSet packet.

Limits: the element serializers of the 21 stub bodies are recording stubs, so the bytes they would write are not
checked (only call order, argument offsets and error hand-back); the layout-b direct writers run with ample room, so
their inlined `finish_grow` path is not reached (the stub fails the case if it is); the element type of the stride-8
bodies is inferred from the writer, not from a type name; the 39 left-out members are listed, not analysed.

Next question: the 979/960 B bodies with the extra `.got` call `0x64e4d08` (six members), and the six members whose
element callee takes another signature (999 B shape, `0x226ca20` family).
