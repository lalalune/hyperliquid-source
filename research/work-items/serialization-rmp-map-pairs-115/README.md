# serialization: rmp map-as-pairs collect path of node #115 (direct and deferred length)

This packet makes it possible to reconstruct, as executable code, how node #115 serializes a collection of
(20-byte address, u64) entries with rmp-serde: the BTreeMap in-order walk, the per-entry `[ "0x"+hex, u64 ]`
array, the length-dependent choice between a direct array header and a deferred 0x80-byte buffer, the
lazy-header flag, and every error and panic exit. The reconstruction (`model` in `tools/rmp_map_pairs_115.py`)
matches the real bytes of 14 bodies (two copy families × 7 functions) on 10,000 generated cases with 0 mismatches,
and 31/31 deliberately wrong reconstructions plus 59/60 reached inverted branches are detected.

- Component ID: `serialization`
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: 7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6
- Claim status: observation (bytes, call templates, evaluated behavior on generated cases); inference (the Rust
  types: `BTreeMap<[u8; 20], u64>` and a slice pair of `([u8; 20], u64)`, rmp-serde `collect_seq`); unresolved
  (the callers that choose this path, and growth of the deferred buffer).
- Scope included: the collect bodies 0x222a7a0 / 0x4155980, BTreeMap `Iter::next` 0x23863d0 / 0x37c4430, the
  direct-path key and value serializers 0x2297f40 / 0x2293c30 and 0x41cf6c0 / 0x41ce7d0, the deferred-path entry
  writer 0x228b8d0 / 0x41bff50 with its key and value serializers 0x22962a0 / 0x2296160 and 0x41ce910 / 0x41cfc10.
  Run for real but not claimed: the rmp leaf writers (array header, uint, str, Compound::end of both serializer
  layouts) and the hex encoder 0x2eabb50. Excluded: the buffer-end routine 0x227e2e0 / 0x41acea0 (contract stub;
  RE-012 snapshot packets describe its handoff), vector growth (reserve and finish_grow fail the case if reached),
  the newtype wrappers that call the collect body (serialization-rmp-newtype-forward-115).

## Reproduce

From the repository root, with Python 3 (standard library only); the binary is read, never executed:

```
python3 tools/rmp_map_pairs_115.py --out research/work-items/serialization-rmp-map-pairs-115
python3 -m unittest tests.test_rmp_map_pairs_115
```

The tool checks the input SHA-256 first and stops on any other binary. One full run takes about 7 minutes
(10,000 cases plus controls). Two runs with `PYTHONHASHSEED=1 TZ=UTC` and `PYTHONHASHSEED=977 TZ=Asia/Seoul` and
`PATH=/usr/bin:/bin` (no binutils needed) gave byte-identical folders. `cases-sample.tsv` keeps every 2nd case;
`summary.json` holds the SHA-256 of all 10,000 case rows (`all_case_rows_sha256`), so the omitted rows are
reproducible from the tool alone.

Files: `bodies.tsv` (the 14 bodies: FDE extent, instruction count, byte SHA-256, call template read from the
bytes), `coverage.tsv` (instructions reached per body and unreached runs), `cases-sample.tsv`, `controls.tsv`
(every control and the first case that catches it), `summary.json`.

## Evidence

Coordinates are virtual addresses in `.text`; extents come from `.eh_frame` FDEs via `tools/fde_extents.py`.
All numbers in the evidence files come from ELF bytes read with Python (`tools/elf_index.py`, `.rela.dyn`
RELATIVE/GLOB_DAT addends for GOT slots).

Call templates (direct `e8`/`e9` targets and rip-relative GOT calls in address order), identical for both copy
families after mapping each family's own leaf addresses; the opcode sequences of the two copies are equal:

| role | 0x226 family | 0x419 family | template |
| --- | --- | --- | --- |
| collect | 0x222a7a0 | 0x4155980 | hdr, malloc, next, entry, hdr, key, value, end, free, bufend, free, add-overflow, alloc-error |
| next | 0x23863d0 | 0x37c4430 | unwrap-none ×2 (GOT 0x64df830) |
| key | 0x2297f40 | 0x41cf6c0 | hdr, uint, free, hex (GOT 0x64e4d08 → 0x2eabb50), str |
| value | 0x2293c30 | 0x41ce7d0 | hdr, uint, free, uint |
| entry | 0x228b8d0 | 0x41bff50 | ekey, evalue, end_a, free, reserve |
| ekey / evalue | 0x22962a0 / 0x2296160 | 0x41ce910 / 0x41cfc10 | as key / value with the layout-a leaves |

Observed behavior (each item is checked by the evaluator on the cases):

1. Length. `cmpq $2,(iter)` selects the slice arm for the length: `((a_end-a_begin)>>5) + ((b_end-b_begin)>>5)`,
   otherwise word 8 of the iterator record. The per-entry arm test is `cmpl $2` (low 32 bits only), and
   `Iter::next` tests the handle tag with `cmpl $1`, so a tag of 0x100000001 is still `Some`.
2. Direct path (`len >> 32 == 0`): array header of `len` (fixarray < 16, array16 < 2^16, else array32; a length of
   0xffffffff writes `dd ff ff ff ff`). Each entry: `92`, key as str8 `d9 2a` + `"0x"` + 40 lowercase hex digits
   (leading zeros kept, encoder flag r8 = 0), value as the smallest msgpack uint, then Compound::end.
3. Flag byte serializer+0xc == 2: the collect body does not write the pair header; the compound starts with
   pending capacity 0 and the key serializer writes the header through the header leaf (call site inside key).
   The bytes are the same; the call site differs (`hdr.key` in the call lists).
4. Errors stop the walk at once. A header/uint/str error becomes `(0x8000000000000000, e0, e1)`; a Compound::end
   error is passed through as its full triple. After the walk the 0x30-byte state `{niche, 2, 0, 0, 0, ser}` goes to
   the buffer-end routine, whose result is the caller's result.
5. Deferred path (`len >> 32 != 0`): `malloc(0x80)` (null → handle_alloc_error panic), state
   `{cap 0x80, ptr, len 0, cfg, count u32 0, ser}` with `cfg = ((u16 ser+0xa | u8 ser+0xc << 16) & 0xff0101) << 16
   | u16 ser+8`. The state is a layout-a serializer: the entry writer puts `92` inline (or defers it when cfg byte
   +0x1c == 2), then the layout-a key, value and end write into the buffer. On error the buffer is freed
   (`sdallocx(ptr, 0x80)`) and the error triple returned; on success the u32 count increments
   (`cmp $0xffffffff` → add-overflow panic, unreachable in practice).
6. BTreeMap layout read by `Iter::next`: parent +0, values `u64[11]` +0x8, keys `[u8;20][11]` +0x60, parent index
   u16 +0x13c, length u16 +0x13e, edges +0x140. A lazy front handle `{1, 0, root, height}` descends edge 0
   `height` times; an exhausted root with remaining length > 0 panics (unwrap on None, GOT 0x64df830).

## Implementation and comparison

The reconstruction is Python, not Rust: `model` with `tree_iter` (a re-implementation of the leaf-edge
`next_unchecked` walk), `slice_iter`, `length_of`, `state_config`, `array_header`, `write_uint`, `write_str`,
`address_text`. The evaluator (`Machine`, shared with earlier serialization packets) runs the real x86-64 bytes of
all 14 bodies, the leaf writers and the hex encoder. Stubs: malloc/free/memcpy (GLOB_DAT imports, checked by
size), the buffer-end routine (contract: records the state it receives, writes the case's result), panic GOTs
(boundary). Faults are injected at any leaf call by index: the leaf is skipped and an error is returned in its
own convention (slot words for header/uint, rax:rdx for str, full triple for end).

Each case compares: panic kind, the ordered list of leaf/stub calls (with the `.key` call site of a lazy header),
appended output bytes, the deferred buffer contents (rest of the 0x80 bytes untouched), the entry-writer
arguments and state at every entry, the state passed to the buffer end, frees, the 24-byte result record,
callee-saved registers, and that inputs are unchanged.

Case modes (deferred 1000, faults 1000, lengths 1000, resume 1000, slices 2000, tree 4000): B-trees of height 0..3 and 9 (empty internal nodes allowed), slice pairs, resumed leaf
handles, wrong lengths and tags, deferred lengths (≤ 2 entries, malloc failure), and fault sweeps.

Controls (111 total, listed in `controls.tsv`):

- 31 model mutants (header limits, uint limits, str8 limit, hex case/prefix/leading zero/length, walk
  order, slice order, value offset, deferred threshold, buffer size, cfg mask, deferred header, missing free,
  frozen count, state word, pair header, field order, end error tag, continue after error, skipped buffer end,
  ignored flag): 31 detected.
- 80 inverted conditional jumps in the seven 0x226 bodies, run on the first 240 0x226-family cases:
  59 of 60 reached sites detected; 20 sites are never reached (listed as
  `unreached`); undetected: ekey:0x2296350. The one undetected site, 0x2296350, is the `je` that skips freeing a zero-capacity
  pending vector in the deferred key serializer. Inverting it adds a `free(1, 0)` call, which can only be observed
  in deferred flag-2 cases that end in an error, and none of the 240 subset cases is one of them.
- Unit tests: wrong binary hash, a corrupted call target in the collect body (template check fails), a model read
  outside case memory, and an inverted branch.

## Results and limitations

- 10,000 cases, 0 mismatches; panics alloc-error 129, unwrap-none 1680; faults injected in 3,076 cases.
- Coverage per body (reached/total instructions): 226:collect 212/251, 226:ekey 72/94, 226:entry 56/85, 226:evalue 35/87, 226:key 72/94, 226:next 120/126, 226:value 37/86, 419:collect 212/251, 419:ekey 72/94, 419:entry 56/85, 419:evalue 35/87, 419:key 72/94, 419:next 120/126, 419:value 37/86.
- Unreached by construction: the value serializers' pending-header arm (the key serializer always clears the
  pending word first), the pending-byte loops and their frees (pending length is always 0 on this path), the
  count-overflow panic, vector growth, and landing pads.
- The deferred path cannot complete from these callers in practice (it needs ≥ 2^32 entries), so it is checked
  only up to an injected error or the iterator panic; the buffer-end routine is a contract stub.
- No gate change is requested.

Next question: which callers reach the newtype wrappers 0x2271df0 / 0x41a58e0 (and so this collect body), and
what does the buffer-end routine 0x227e2e0 write for the deferred state?
