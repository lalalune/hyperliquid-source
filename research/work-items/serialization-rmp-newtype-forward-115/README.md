# serialization: reconstruct 59 forwarding rmp-serde newtype serializers of node #115 (collection iterators and field tuples)

**What this makes reconstructable:** a Rust port can now reproduce, for 59 `serialize_newtype_struct` bodies
of node #115, the exact iterator record that is handed to the inner `collect_seq` for a two-representation
collection (B-tree map or ring buffer), and the exact array header, field addresses, call order and
error propagation of the n-field tuple newtypes. Before this packet these bodies were only rows in mass
call-site tables, or named as the "next question" of the earlier leaf-only newtype packet. The record covers:

- the `_ExtStruct` gate. Seq bodies return the static 14-byte `expected tuple` error (word 0 `0x8000000000000002`).
  Tuple bodies return the 21-byte `expected i8 and bytes` error. Neither touches the buffer or calls anything.
- **seq family (29 bodies, 3 copy families)**: value word 0 is a niche. `0x8000000000000000` selects the
  B-tree arm (root `+8`, height `+0x10`, length `+0x18`). Any other word 0 is a ring-buffer capacity
  (pointer `+8`, head `+0x10`, length `+0x18`).
  - B-tree arm: the record is `[f, 0, root, height, f, 0, root, height, root ? len : 0]` with `f = root != 0`.
  - Ring arm: `phys = head >= cap ? head - cap : head`, `room = cap - phys`.
    - If `len == 0`, all four slice words are the buffer pointer.
    - If `len > room` (unsigned), the slices are `[phys, cap)` and `[0, len - room)`.
    - Otherwise they are `[phys, phys + len)` and an empty slice at the buffer start.
    - Addresses are `ptr + i * elem` modulo 2^64, with `elem` = 0x20, 0x30 or 0x68 (read from `shl`/`lea`/`imul`
      bytes). Only words 0..4 are defined for this tag; words 5..8 are enum padding.
  - The body forwards `(out, ser, &record)` to its own inner collect and returns whatever that writes into `out`.
- **tuple family (30 bodies, 3 copy families, 2 serializer layouts)**: array header `0x90|n` (n = 2 or 3).
  - Layout b (`&mut Vec<u8>` serializer) always calls the header writer (`0x25e7940` / copy `0x3d50270`). It tests the serializer
    byte `+0xc == 2`, but both arms make the same call (only the stack slot differs), so the flag is inert.
  - Layout a (inline `Vec<u8>`) calls the header writer (`0x25e7c10` / `0x3d50540` / `0x57cee80`) only when
    byte `+0x1c == 2`. Otherwise it stores the header byte inline and calls `reserve(vec, len, 1, 1, 1)`
    (`0x231e050` / `0x43bd910` / `0x5963a10`) when the buffer is full.
  - Then the inner field serializer runs on `value + stride * i`. The argument order and stride are per body:
    `(slot, value, ser)` with stride 0x20 or 0x10, or `(slot, ser, value)` with stride 0x18. The stride is
    re-read from the bytes (the pointer step between field calls) and must equal the declared one. The body stops at
    the first result whose word 0 is not `0x8000000000000004` and copies that 24-byte result to `out`.
  - Then it calls Compound::end (b: `0x22997f0` / `0x41d3f60`; a: `0x22999e0` / `0x41d4150` / `0x5325140`)
    with `{0x8000000000000000, 1, 0, ser, 2}`.
- How an error from any fallible call (header writer, each field, end) propagates.

A pure-Python reconstruction (`model`, `ring_record`, `tree_record`) was checked against the real machine code
(evaluated, not executed) in **11,800 cases with 0 mismatches**. The 59 bodies ran together with the real
header writers and Compound::end of both layouts in all three copy families (10 leaf functions). The 59 inner
serializers (one per body) were argument-checking contract stubs. **5,116/5,116 body instructions** were
reached, and **417/417 negative controls** were detected: 27 wrong-model mutants and 390 single-bit corruptions of body bytes (name length, reserved-name bytes,
message length, element stride, `cmovae` wrap, header count, field step, layout-a flag offset, inline header
byte, inner call displacement).

- Component ID: `serialization` (MessagePack value encoders). No gate is requested.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: written against main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No reference
  source was used.
- Claim status:
  - **Observation**: every byte-level behavior above. It is checked by evaluating the original bytes, and the
    tool re-reads each body's callees, message, header count, flag offset, element stride and field stride
    from the ELF.
  - **Inference**:
    - The Rust type names. "B-tree map or ring buffer" is inferred from the record shapes: the LazyLeafRange-like
      `(Some, root, height)` handles plus a length, and the `as_slices` arithmetic of `VecDeque`.
    - Reading the inner targets as `collect_seq` / field `Serialize::serialize`.
- Scope included: the 59 bodies listed in `bodies.tsv`:

  | copy family | seq | tuple (layout b / a) | range |
  |---|---|---|---|
  | 0x226 | 10 | 7 / 7 | 0x226b570..0x2278390 |
  | 0x419 | 9 | 5 / 5 | 0x419a200..0x41a6b90 |
  | 0x52f | 10 | 0 / 6 | 0x52f0ef0..0x52fda50 |

- Scope excluded:
  - the inner serializers themselves (stubbed; listed per body)
  - `0x226b810`, which calls the unrelated leaf `0x25e85a0`
  - `0x419b640` and `0x419b4d0`, whose addresses appear as a range in an RE-003 packet, and `0x41a0f20`, which
    appears in an unrelated #94 draft table
  - the leaf-only newtypes drafted earlier

## Reproduce

From the repository root, with `artifacts/node/115/hl-node` present (SHA-256 above). Python 3 standard library
only; no external programs; the binary is never executed.

```
python3 tools/rmp_newtype_forward_115.py --out research/work-items/serialization-rmp-newtype-forward-115
python3 -m unittest tests.test_rmp_newtype_forward_115
```

The generator takes about 25 s, and the unittest takes about 70 s. Two runs into different folders, with
different `PYTHONHASHSEED` and `TZ`, produce byte-identical files. `outputs_sha256` in `summary.json` hashes the
written bytes, result record and inner-call records of all 11,800 cases. `cases-sample.tsv` keeps the rows with
`k % 16` in {2, 4, 9, 13}, which is 2,950 rows covering every arm.

## Evidence

Coordinates are virtual addresses in `.text`, and function extents are `.eh_frame` FDE ranges read with
`tools/fde_extents.py`. Human-readable excerpt (objdump, not used by the tool) of the ring arm of seq body
`0x2271df0` (elem 0x20):

```
2271e4f: mov    0x18(%r8),%rdi        ; len
2271e53: test   %rdi,%rdi
2271e56: je     2271ea3               ; len == 0 -> all slices at ptr
2271e58: mov    0x10(%r8),%rdx        ; head
2271e5c: xor    %ecx,%ecx
2271e5e: cmp    %rax,%rdx             ; head >= cap ?
2271e61: cmovae %rax,%rcx
2271e65: sub    %rcx,%rdx             ; phys
2271e68: mov    %rax,%r9
2271e6b: sub    %rdx,%r9              ; room = cap - phys
2271e6e: mov    %rdi,%rcx
2271e71: sub    %r9,%rcx              ; len - room
2271e74: ja     2271ea9               ; wrapped
2271e76: add    %rdx,%rdi             ; phys + len
...
2271ead: shl    $0x5,%rdx             ; * elem
2271ec2: mov    $0x2,%r8d             ; tag 2
2271f01: call   222a7a0               ; inner collect (out, ser, &record)
```

Generated files (all are rebuilt byte-for-byte by the tool):

| file | content |
|---|---|
| `bodies.tsv` | per body: FDE end, instruction count, copy family, family, layout, element stride or field count, field order/stride, inner target and its FDE end, ext message address, length and text, ordered direct callees |
| `cases-sample.tsv` | sampled cases: arm, name, flag, fault position, value words, the inner arguments seen (seq record words or field order@offset), inner result tags, buffer length and hash, 24-byte result |
| `controls.tsv` | 417 negative controls, each with the index of the first case that exposes it |
| `coverage.tsv` | executed/total instructions per body and per real leaf writer (10 copies) |
| `summary.json` | counts, arms, stub list and the all-cases output hash |

Static checks that the tool enforces from the bytes (it fails if any of them changes):

- every body and inner target starts an FDE
- each body has exactly one inner callee (the declared one) and no `.got` calls
- seq bodies call nothing else, and their element stride is the `shl` count (times 3 after `lea (r,r,2)`) or the
  `imul` immediate
- tuple bodies have the ordered call list header (x2 in layout b), inner x n, end (+ reserve in layout a)
- the header count immediate is n, and the pointer step between field calls is the declared field stride
- the flag test is at `+0xc` (b) or `+0x1c` (a)
- layout a stores the inline byte `0x90|n`
- the name test compares against `_ExtStruct` with length 10, and the ext message text is one of the two known
  rmp-serde strings

## Implementation and comparison

- Reconstruction: `tools/rmp_newtype_forward_115.py`, functions `model`, `ring_record`, `tree_record`,
  `seq_record` and `is_ext`. No Rust implementation yet ("not yet implemented"), and no gate requested.
- Comparison: a concrete x86-64 evaluator (shared with the earlier newtype packets) runs each body's original
  bytes from the ELF.
  - Real callees: the array header writers and Compound::end of both layouts in each copy family
    (`0x25e7940`, `0x25e7c10`, `0x22997f0`, `0x22999e0`, `0x3d50270`, `0x3d50540`, `0x41d3f60`, `0x41d4150`,
    `0x57cee80`, `0x5325140`). They are used as dependencies, not claimed here.
  - Contract stubs:
    - each inner serializer checks the out slot, the serializer pointer and the argument order, records the
      72-byte record or field address, writes the case's 24-byte result, and scrambles caller-saved registers
      and xmm
    - `reserve` (`0x231e050`, `0x43bd910`, `0x5963a10`) with its argument contract
    - memcpy
  - Compared per case:
    - the appended buffer bytes and the untouched rest of the serializer
    - the 24-byte result record
    - the return register
    - the ordered fallible-call list
    - every inner argument (all 9 words for tag 0/1, words 0..4 for tag 2, order and offset for fields)
    - callee-saved registers, stack balance and unchanged inputs
- Cases: 200 per body.
  - Names: the reserved name, single-bit near misses at every position, prefix/suffix, case variants and random
    names.
  - Ring values: empty, contiguous, wrapped, exact split, split+1, head ≥ cap, full, zero capacity and arbitrary
    words. Tree values: with and without a root.
  - Inner results: Ok, and errors with tags close to Ok (`0x8000000000000005`, `0x8000000000000104`, `4`, ...).
  - A fault injected at each fallible-call position.
- Arms: ext 1,475; ring empty 360, contiguous 880, wrapped 935; tree without root 1,044, with root 1,856;
  tuple ok 1,781, inner error 1,759, writer/end fault 1,710.
- Negative controls (all detected):
  - 27 model mutants: ext prefix/case/len9/tag/message length, empty as general, no wrap subtraction, `>`
    instead of `>=` wrap, room from raw head, wrong element size, wrong first-slice end, second slice from head,
    tag 1, tree flag inverted, tree length always, tree height 0, niche ignored, seq forced Ok, header count+1,
    stride+8, argument order swapped, Ok by low tag byte, continue after error, error tag, layout-a flag
    inverted, end skipped, error keeps bytes.
  - 390 single-bit byte flips over all 59 bodies.
  - Tests add digest corruption, a body address that starts no FDE, a wrong declared element stride, a wrong
    declared field stride and a wrong declared inner target. They also cover hand-built ring and tree values
    on every element stride, a fault at every call position, the first failing field stopping the tuple, the
    layout-a inline header with a full buffer, and per-copy-family byte controls (40 tests).

### Port sketch (the reconstructed semantics, as Rust-shaped pseudocode)

```
fn seq_newtype(out, ser, name, value: &[u64; 4], elem, inner) {
    if name == "_ExtStruct" { *out = Err(Static("expected tuple")); return; }   // tag 0x8000000000000002
    let rec = if value[0] == 1 << 63 {                // B-tree arm
        let (root, height, len) = (value[1], value[2], value[3]);
        let f = (root != 0) as u64;
        [f, 0, root, height, f, 0, root, height, if root != 0 { len } else { 0 }]
    } else {                                          // ring arm: (cap, ptr, head, len)
        let (cap, ptr, head, len) = (value[0], value[1], value[2], value[3]);
        let at = |i: u64| ptr.wrapping_add(i.wrapping_mul(elem));
        if len == 0 { [2, ptr, ptr, ptr, ptr, ..] } else {
            let phys = if head >= cap { head - cap } else { head };
            let room = cap.wrapping_sub(phys);
            if len > room { [2, at(phys), at(cap), ptr, at(len - room), ..] }
            else { [2, at(phys), at(phys + len), ptr, ptr, ..] }
        }
    };
    inner(out, ser, &rec);                            // result passes through unchanged
}

fn tuple_newtype(out, ser, name, value, n, stride, inner) {
    if name == "_ExtStruct" { *out = Err(Static("expected i8 and bytes")); return; }
    write_array_header(ser, n)?;                      // inline 0x90|n on layout a unless flag == 2
    for i in 0..n { inner(value + stride * i, ser)?; } // first non-Ok result is returned as-is
    *out = compound_end(ser, {1 << 63, 1, 0, ser, 2});
}
```

## Results and limitations

- 11,800 / 11,800 cases match.
- 417 / 417 controls detected.
- 5,116 / 5,116 body instructions reached.
- The real leaf writers are only partly reached (header 51/179 and 49/83, end 25/130 and 24/96 in each copy). Their own arms belong to the
  leaf packets.
- Two flips are **equivalent by construction** and are not used as controls:
  - the layout-b flag offset, since both arms call the same header writer
  - `len >= room` versus `len > room`, since the exact-fit split gives the same slices
- Unknown:
  - the Rust type behind the B-tree/ring-buffer niche, and the element types (0x20/0x30/0x68 bytes)
  - what the 43 inner serializers write; they are stubbed by contract
  - why the field stride differs between tuple bodies (0x10, 0x18, 0x20): the field types are not named
- No progress gate is requested; this covers the forwarding bodies only.

Next question: what do the inner `collect_seq` targets (for example 0x222a7a0, elem 0x20) do with the
72-byte record? In particular, does the B-tree arm walk `height` levels to the first leaf before emitting the
`len`-element MessagePack array?
