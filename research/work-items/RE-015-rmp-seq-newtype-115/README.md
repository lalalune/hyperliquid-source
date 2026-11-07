# RE-015: rmp-serde newtype(Vec<T>) serializers — direct and buffered sequence paths (node #115)

This packet makes it possible to rebuild the MessagePack writer for every `newtype(Vec<T>)` field of the
0x226/0x419/0x52f serializer copy families: 54 bodies in three copy families now have an executable Python model.
The model covers the reserved-name reject, the u32 length split between "header first, write straight through"
and "buffer into a 0x80-byte compound, count, then header + copy", the config bits the compound keeps
(mask 0xff0101), the element-error hand-back and the buffer release. The model was checked against the real bytes
on 10,800 body cases plus 1,800 direct Compound::end cases cases with 0 mismatches.

- Component ID: `constants` (RE-015 serializer/string-reference work; the rmp encoders of earlier RE-015 packets)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: lalalune/hyperliquid-source main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`;
  no reference source used (references/can1357-hl was not consulted for these bodies)
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (the rmp-serde names `serialize_newtype_struct`, `MaybeUnknownLengthCompound`, `Compound::end`)
- Scope included: the 54 bodies in `bodies.tsv`, their copy family's array-header writer (6 bodies) and
  Compound::end (6 bodies) run for real. Excluded: the element serializers (80 distinct callees, recording stubs),
  `0x41a3070` (named in another pending packet) and `0x419d8a0` (named in merged `RE-010-cancel-routing-115`).
  The Compound::end bodies `0x227e2e0`/`0x227e1b0` already have disassembly listings in RE-012 snapshot packets.
  Here they run only as dependencies and are not claimed. No progress gate is requested.

## Reproduce

From the repository root (Python 3 standard library only; binutils not needed; the binary is never executed):

```
python3 tools/re015_rmp_seq_newtype_115.py --out research/work-items/RE-015-rmp-seq-newtype-115
python3 -m unittest tests.test_re015_rmp_seq_newtype_115
```

- The tool checks the input SHA-256 first and stops on any other binary.
- It writes `bodies.tsv`, `family-scan.tsv`, `cases-sample.tsv`, `end-cases-sample.tsv`, `controls.tsv`,
  `coverage.tsv` and `summary.json`.
- Two runs with different `PYTHONHASHSEED`, `TZ` and `PATH` give byte-identical files.
- A full run takes about 150 s. Almost all of that is the byte-flip controls.
- Case generation is a SHA-512 counter stream keyed by body address.
- `--per-body N` changes the case count (default 200 per body).

## Evidence

Coordinates are virtual addresses in node #115 (`.text` VA = file offset + 0x400000 is not assumed; the tool maps
through the section headers via `tools/elf_index.py`). FDE extents come from `tools/fde_extents.py`.

### Body shape (every number is read from bytes by `body_facts`)

Human-readable excerpt (`objdump -d -M intel`, not used by the tool) of `0x2273370`, layout b, stride 0x120:

```
2273389: cmp    rcx,0xa                     ; name length
227338f: movabs rax,0x757274537478455f      ; "_ExtStru" ... xor/or with "ct"
22733aa: je     227366e                     ; -> {0x8000000000000002, 0x5e90a1 "expected tuple", 14}
22733b0: mov    r14,[r8+0x8] ; mov rdx,[r8+0x10]      ; Vec ptr, len
22733b8: shl rax,5 ; lea rbp,[rax+rax*8]    ; len * 0x120 (wrapping)
22733c3: shr    rax,0x20 ; sete cl          ; len fits in u32?
22733cd: cmp    BYTE PTR [r15+0xc],0x0      ; flag only selects first-element peeling
2273402: jne    227350a                     ; len >= 2^32 -> buffered compound
227341a: call   25e7940                     ; write_array_len(len as u32)
2273499: call   23f7be0                     ; element serializer on the outer serializer
22734e6: call   227e2e0                     ; Compound::end (word0 = 0x8000000000000000 -> Ok at once)
2273515: call   [malloc] edi=0x80           ; buffered: Vec<u8> with capacity 0x80
2273542: and    edx,0xff0101                ; config bits copied into the compound
22735cb: call   23f7e60                     ; element serializer on the compound (a layout-a monomorph)
22735db: cmp    eax,0xffffffff ; je panic   ; u32 element count, Location 0x642c1e0, GOT 0x64df520
```

`body_facts` demands, for every body:

- **Calls:** exactly six direct calls besides `_Unwind_Resume`, in the order header writer, direct element,
  direct element, Compound::end, direct element, compound element.
- **Layout and family:** the compound element equals the direct one exactly for layout a. Compound::end and the
  header writer match the declared copy family and layout.
- **GOT calls:** exactly the four slots malloc `0x64df480`, handle_alloc_error `0x64df498`, sdallocx
  `0x64df4a0` and the count-overflow panic `0x64df520`.
- **Stride:** one stride, from the `add r, +s` / `add r, -s` pair, equal to the declared stride.
- **Flag test:** one flag test at +0xc (layout b) or +0x1c (layout a).
- **Constants:** the constants 0x80, 0xff0101 and 2^63.
- **Name test:** the 10-byte name compare.
- **Ext arm:** an ext-arm message whose bytes read `expected tuple`.

The derived columns are in `bodies.tsv`.

### Family completeness (`family-scan.tsv`)

`family_scan` reads every FDE in 0x2260000-0x2280000, 0x4190000-0x41b0000 and 0x52f0000-0x5300000 that contains
the `_ExtStruct` movabs and an `e8` rel32 call to one of the six Compound::end copies. The table marks each one as
modelled, excluded (two bodies, with the reason) or other-shape. Other-shape bodies are tuple, map and struct
serializers that also end through Compound::end, which this packet does not model. The tool fails if a modelled
body is missing from the scan or an excluded one is not in it. A unit test also shows that the two excluded bodies
pass the same six-call check; they are left out only because of ownership.

### Compound::end on its own (`end-cases-sample.tsv`)

The six Compound::end copies (`0x227e2e0`/`0x227e1b0`, `0x41acea0`/`0x41acd70`, `0x5306e90`/`0x5306d60`) also
get direct calls with compound records the bodies never build. These reach two arms the bodies cannot:

- **cap = 0:** header and copy happen, but there is no free.
- **cap = 0x100 or 0x41:** the free size follows the capacity word.

The other cases cover:

- **Direct mark:** cap = 2^63 returns Ok with no header.
- **Header errors:** the buffer is freed, then the error comes back.
- **Count values:** 0, 15, 16, 0xffff, 0x10000 and 0xffffffff, including the u32 header width.
- **Buffer lengths:** every length 0..0x80.

### Facts the evaluator established (original instructions, generated inputs)

1. **Name reject.** A name equal to `_ExtStruct` (length 10) returns `{0x8000000000000002, 0x5e90a1, 14}` with no
   other effect. Every one-bit near miss, the 9-byte prefix and an 11-byte extension serialize normally.
2. **Direct path (len < 2^32).**
   - The body writes the array header first: fixarray below 16, `dc` up to 0xffff, `dd` from 0x10000.
   - It then calls the direct element serializer with `(slot, ptr + i*stride, ser)` for i = 0..len.
   - Compound::end then sees word0 = 2^63 and returns Ok without writing anything.
   - The flag byte (+0xc / +0x1c) only decides whether the first element is peeled out of the loop. The output
     and the call sequence are the same either way.
3. **Buffered path (len >= 2^32).**
   - The body allocates 0x80 bytes, failing through `handle_alloc_error(1, 0x80)`.
   - It builds the compound `{cap 0x80, ptr, len 0, cfg, count u32 0, ser}`, where
     `cfg = u16(+0) | ((u16(+2) | u8(+4) << 16) & 0xff0101) << 16` over the serializer's config bytes.
   - Each element goes to the compound element serializer, and the body counts it.
   - Compound::end writes `write_array_len(count)` to the outer serializer, appends the buffer and frees it
     (`sdallocx(ptr, 0x80, 0)`).
4. **Element walk.**
   - The walk stops at `ptr + len*stride` computed mod 2^64.
   - The buffered loop calls the first element before it tests the remaining byte count.
   - So a buffered length whose `len*stride` wraps to `m*stride` serializes exactly m elements. The cases use
     `len = m + j*2^(64 - tz(stride))`.
   - When `len*stride` is not a multiple of the stride, the walk never ends; only an element error stops it.
5. **Errors.**
   - An element serializer result whose word 0 is not `0x8000000000000004` is copied verbatim (all three words)
     to the caller. In the buffered path the 0x80 buffer is then freed.
   - Header-writer errors become `{2^63, e0, e1}`.
   - A header error inside Compound::end also frees the buffer.
6. **Unreached arms (listed in `coverage.tsv`):**
   - The u32 count-overflow panic, which needs 2^32 elements.
   - The buffered-loop arm that switches to the direct element serializer when the compound's capacity word is
     2^63. No element serializer writes that value.
   - The header writers' growth arm (`finish_grow`). The cases leave room, and reaching it is a tool error.

## Implementation and comparison

- **Model.** `tools/re015_rmp_seq_newtype_115.py::model` predicts three things for a call: the appended bytes,
  the 24-byte result record (or a no-return boundary) and the ordered event list. Events are header lengths,
  element offsets, and compound state at each compound element (count, buffer length, config word), plus
  allocation and release. The independent Rust path is not yet implemented.
- **Evaluator.** A concrete x86-64 subset evaluator (same as the earlier RE-015 rmp packets) runs the original
  bytes of each body, its header writer and its Compound::end. The writer's `Marker::to_u8` helper also runs.
  - Contract stubs: reserve `0x231e050`, memcpy, malloc and sdallocx.
  - Recording stubs: the element serializers. Each appends one byte per element, so the buffer copy in
    Compound::end is visible.
  - Header writers can be faulted at any event index.
- **Results:** 10,800 body cases (direct ok 4,320 / direct fault 2,322 / buffered ok 1,080 / buffered fault 1,350 / alloc error 378 / ext error 1,350) and 1,800 Compound::end cases, all with 0 mismatches. 10,146 of 11,668 body instructions executed; the rest are landing pads, the count-overflow panic and the capacity-2^63 arm. Outputs digest `09ac8481f694a9f19bc35e1b6268faf3360290b9f073f2959d41c88d464a4140`.
- **Negative controls (`controls.tsv`, 305 total, all detected):**
  - 21 (15 body + 6 Compound::end) wrong-model mutants: header bounds, header width, name prefix, error tags and message length,
    config mask, u32 split at 2^31, buffered count off by one, stride + 8, element error re-tagged, no free on
    error, count + 1 in the header, no buffer copy.
  - 279 (270 body + 9 Compound::end `jno`/`cmp rax,2`) one-bit byte flips in every body: the name length 10, the `shr 0x20` split, the 0x80 buffer size,
    the 0xff0101 mask and the message length 14.
  - 5 out-of-range inputs: a body address that is not an FDE start, a wrong declared stride, layout or
    copy family, and a corrupted binary digest.

## Results and limitations

`summary.json` holds the machine-readable numbers: 54 bodies, 11,668 body instructions (10,146 executed), 10,800 + 1,800 cases, 0 mismatches, 305/305 controls detected, 80 element-serializer stubs, family scan 122 members = 54 modelled + 2 excluded + 66 other-shape.

**Limits:**

- The element serializers (80 callees) are not modelled. The packet only fixes how they are called and how their
  results are used.
- The count-overflow panic and the capacity-2^63 arm inside the buffered loop are unreachable with real inputs.
  They are shown unreached and are not modelled beyond the static constants.
- The two 919-byte bodies (`0x22768f0`, `0x226e650` and their copies) satisfy the same call pattern; they differ
  only by register allocation.
- Real Rust slices cannot reach a length of 2^32 elements of these sizes on a 64-bit host with this much memory.
  The buffered path is still the code the binary carries for those lengths.

No progress gate is requested.

**Next question:** what do the element serializers write? `0x23f7be0`/`0x23f7e60` (0x120-byte elements) and
`0x22cfa50`/`0x22cfc40` (0x30) are the largest shared pairs. Also, which struct fields own these 54 newtypes?
