# RE-015: rmp-serde newtype(BTreeSet<u32>) serializers and the B-tree Iter::next they drive (node #115)

This packet makes it possible to rebuild, as one executable Python model, the MessagePack writer of every
`newtype(BTreeSet<u32>)` field in the 0x226/0x419/0x52f serializer copy families together with the B-tree
`Iter::next` underneath it: the node layout (parent, `u32` keys, parent index, length, edges), the lazy first-edge
descent, the parent walk, the right-edge descent, the remaining-length counter and its two "unwrap on None" panics,
and the body's reserved-name reject, u32 length test, array header, key stream and counted-compound path. The model
was checked against the real bytes of 6 bodies, 3 `Iter::next` copies, 6 header writers, 6 distinct unsigned-integer
writers and 6 `Compound::end` copies on 12,900 cases with 0 mismatches, and 192 of 192
negative controls were detected.

- Component ID: `constants` (RE-015 serializer/string-reference work)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: lalalune/hyperliquid-source main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; no reference source
  used (references/can1357-hl was not consulted for these bodies)
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (the rmp-serde / `std::collections::BTreeSet` names)
- Scope included: the six 658-byte bodies in `bodies.tsv` and the three 471-byte `Iter::next` copies in
  `iter-next.tsv`; the header writer, unsigned-integer writers and `Compound::end` they call run for real.
  Excluded: the other 658/727/850-byte `_ExtStruct` shapes (see Next question), `Compound::end` as a claim (a
  dependency here), the output Vec growth path `finish_grow`, and the element types other than `u32`. No progress
  gate is requested.

## Reproduce

From the repository root (Python 3 standard library only; binutils not needed; the binary is never executed):

```
python3 tools/re015_btreeset_u32_115.py --out research/work-items/RE-015-rmp-btreeset-u32-115
python3 -m unittest tests.test_re015_btreeset_u32_115
```

- The tool checks the input SHA-256 first and stops on any other binary.
- It writes `bodies.tsv`, `iter-next.tsv`, `cases-sample.tsv`, `next-cases-sample.tsv`, `controls.tsv`,
  `undetected-flips.tsv`, `coverage.tsv`, `summary.json` and `measure.json`.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical files (checked: all 9 files).
- A full run takes about 500 s and peaks at about 493 MB resident. Cases are generated and evaluated one at
  a time; only the comparison result and the written bytes are kept.
- Case generation is a SHA-512 counter stream keyed by body address. `--per-body N` (default 1500) and
  `--per-next N` (default 1300) change the case counts.

## Evidence

Coordinates are virtual addresses in node #115; sections are mapped through `tools/elf_index.py`, FDE extents come
from `tools/fde_extents.py`. Every number in the tables is read from ELF bytes by the tool.

### Body shape

Human-readable excerpt (`objdump -d -M intel`, not used by the tool) of `0x2270e30` (family 0x226, layout a):

```
2270e46: cmp    rcx,0xa                     ; name length; "_ExtStruct" movabs/xor test follows
2271048: ... 0x5e90a1 "expected tuple", 14  ; reserved name -> {0x8000000000000002, ptr, 14}
2270e6d: mov    rax,[r8] ; mov rcx,[r8+8]   ; set record {root, height, length}
2270e7c: setne  sil ; mov rdx,[r8+0x10]     ; tag = root != 0; length is read only if there is a root
2270e93: shr    rdi,0x20                    ; length >= 2^32 -> buffered compound (2270f03)
2270ee8: call   25e7c10                     ; array header (low 32 bits of the length)
2270f83: call   23885b0                     ; Iter::next(&iter) -> *key or null
2270f9d: call   25e9f10                     ; write_uint(&mut res, ser_or_compound, key as u64)
2270fcc: cmp    eax,0xffffffff              ; buffered only: counter overflow -> panic (Location 0x642c1e0)
2271002: call   227e1b0                     ; Compound::end (word0 0x8000000000000000 -> Ok at once)
```

The iterator record on the stack is `[tag, 0, root, height, 1-or-0, 0, root, height, length]` (front half at
`rsp+0x68`, back half copied and never read, remaining length at `+0x40`).

### Iter::next shape (`0x23885b0`)

```
23885b1: mov    rax,[rdi+0x40] ; test ; je   ; remaining length 0 -> return NULL, nothing else touched
23885ba: dec    rax ; mov [rdi+0x40],rax     ; decrement BEFORE the traversal
23885c1: cmp    dword [rdi],1 ; jne 2388778  ; front not Some -> panic(Location 0x642e318)
23885ca: mov    rcx,[rdi+8] ; test ; je      ; node 0 = lazy: [rdi+0x10]=root, [rdi+0x18]=height
2388620: mov    rcx,[rcx+0x38]               ; lazy descent: first edge, `height` times (8x unrolled at 2388640)
2388666: mov    [rdi],1 ; mov [rdi+8],rcx    ; front becomes {1, leaf, height 0, idx 0}
23885db: movzx  edx,word [rcx+0x36]          ; node length; idx >= length -> ascend
2388690: mov    rdx,[rcx] ; test ; je 2388769 ; parent; none -> panic(Location 0x642fbc0)
238869f: movzx  eax,word [rdx+0x34]          ; parent index of the child we came from (height += 1)
2388739: lea    rax,[rdx+rax*4+8]            ; key pointer = node + 8 + 4*idx
23886b1: lea    rcx,[rdx+rax*8+0x40]         ; next position: edges[idx+1], then first edges down to a leaf
```

### Tables

- `bodies.tsv`: the 6 bodies (family, layout, header writer, `Iter::next`, direct and compound unsigned writers,
  `Compound::end`, "expected tuple" message). Each body has exactly 5 direct calls besides `_Unwind_Resume`, one
  `shr 0x20`, and the four `.got` calls malloc / handle_alloc_error / sdallocx / count-overflow panic.
- `iter-next.tsv`: the 3 `Iter::next` copies, both panic Locations (read from the two `lea rdi,[rip+..]`), and
  every base+displacement used (0x8, 0x10, 0x18, 0x34, 0x36, 0x38, 0x40, ...).
- `cases-sample.tsv`, `next-cases-sample.tsv`: every 4th body case / every 4th direct `next` case with its inputs
  (root, height, node and key counts, record length, config, fault, room), written bytes (hash), result record and
  an event summary. The full case set is regenerated by the tool.
- `controls.tsv`: the negative controls and the index of the first case that detects each.
- `undetected-flips.tsv`: byte flips of reached instructions for which no sampled case differs (see Limits).
- `coverage.tsv`: instructions reached per function on every 7th case (0x227e1b0 23/91; 0x227e2e0 23/123; 0x23885b0 92/125; 0x25e7940 74/179; 0x25e7c10 75/83; 0x25e9c70 72/165; 0x25e9f10 189/240; 0x37c7d20 92/125; 0x3d50270 74/179; 0x3d50540 75/83; 0x3d51450 189/240; 0x3d517e0 72/164; 0x41acd70 23/91; 0x41acea0 23/123; 0x513b420 92/125; 0x5306d60 23/91; 0x5306e90 23/123; 0x57ceba0 75/185; 0x57cee80 75/83; 0x57cfd20 189/240; 0x57d00b0 61/103).
- `summary.json`, `measure.json`: totals and a digest over all case outputs.

### Ownership and overlap check

- A text scan of `research/` finds the bodies and the three `Iter::next` copies only as address mentions in RE-001
  caller censuses; none of the addresses appears in an open or merged PR title or file list (`open.json`, checked
  in the run that produced this packet).
- The shared unsigned-integer writers, header writers and `Compound::end` copies appear in other packets as
  listings or dependencies (the VecDeque<u64> and Vec<T> packets); this packet runs them and claims their
  behaviour only for the BTreeSet path.
- The sibling `Iter::next` at `0x2388790` (node displacements 0xe4 / 0xe6 / 0x1d0) is a different instantiation and is
  not part of this packet.

## Implementation and comparison

`tools/re015_btreeset_u32_115.py` holds (1) a pure-Python x86-64 subset evaluator that runs the original bytes
(the evaluator of the earlier RE-015 rmp packets, copied to keep the packet standalone), and (2) the reconstruction:

- `Tree` / `Tree.image()`: plain description of a B-tree and its byte image: `parent` at +0, `u32` keys from +8,
  parent index `u16` at +0x34, length `u16` at +0x36, edges from +0x38; unused key slots hold 0xa5 fill.
- `next_model(record, tree)`: `Iter::next` on the 9-word record: zero remaining length returns null untouched;
  decrement; tag must be 1; lazy root (node word 0) descends `height` first edges; ascend while `idx >= len`
  (panic at the root, height + 1, idx = parent index); key = (node, idx); next position is `(node, idx+1)` at
  height 0, otherwise `edges[idx+1]` followed by `height-1` first edges.
- `body_model(case)`: reserved-name reject; remaining length = 0 when there is no root (the length word is not
  read); `length >> 32 == 0` selects the direct path (array header of the low 32 bits, then every key through the
  unsigned writer), otherwise malloc(0x80) and the counted compound; a walk that runs past the last key ends in
  the root panic after all keys were written.
- `write_array_len`, `write_uint`: marker byte first, payload second, with the exact reserve calls.
- `reference_bytes(sorted_keys)`: an independent oracle for valid sets (strictly increasing in in-order position):
  the output must equal the MessagePack array of the sorted keys.

Comparison: for every case the evaluator checks written bytes (also before a panic), the 24-byte result record, the
ordered event list (header writes with their u32, every unsigned-writer call with value, serializer kind, counter
and compound config word, reserve calls, malloc/free with sizes), the panic Location or allocation-error
arguments, that the tree image and the set record are unchanged, and the callee-saved registers. Direct
`Iter::next` cases check the returned key pointer, all nine iterator words (the unused back half must stay) and
the panic Location. Fault injection fails the k-th header or unsigned-writer call with a distinguishable result.

- Case set per body: absent root (record length ignored), single leaves (including an empty root leaf), heights
  1-3 trees of up to 60 nodes, exact / shorter / longer record lengths, header-form boundary lengths (0xf, 0x10,
  0xffff, 0x10000, 0xffffffff), wide lengths (2^32.. and 2^63..) with and without allocation failure, reserved
  names and one-bit name variants, faults in the header and in element writes, small output room so the reserve
  contract is hit. Direct `next` cases take every iterator state along the whole walk of random trees, with
  remaining length 0, tags 0/2/0x100000001/0xffffffff and random back-half words.
- Negative controls (192): 19 model mutants (header forms, name test, config mask, split, error tags,
  release, three unsigned bounds, tag test, lazy descent, right-edge descent, edge index, parent index, length
  bound), 167 byte flips of reached instructions (conditional jumps, immediates, displacements) in the bodies,
  the `Iter::next` copies and the shared callees, and 6 range controls (address that is not an FDE start,
  `Iter::next` not at an FDE start, declared `next` wrong, declared `Compound::end` wrong, wrong panic Location,
  flipped binary digest).

## Results and limitations

- 12,900 cases, 0 mismatches; case kinds (`summary.json`): alloc error 307, buffered fault 364, buffered panic 853, direct fault 803, direct ok 2,095, direct ok valid 1,190, direct panic 940, empty set 1,320, ext error 1,128, next bad tag 261, next empty 354, next lazy 60, next mid 3,225.
- 192 / 192 negative controls detected; 13 further byte flips of reached instructions
  were not distinguished by the sampled cases and are listed in `undetected-flips.tsv` instead of being claimed.
- Own tests: 40 unittest cases pass; `artifacts.py verify` and `catalogue.py --check` were run with the
  packet in place.
- Findings (observation):
  - The remaining length is decremented before the traversal and before the tag test: a record whose length word
    is 0 returns null without touching anything, even with a corrupt tag.
  - The body reads the record length only when the root is non-null; an absent root writes an array header of 0
    whatever the length word says.
  - The header carries the record length (low 32 bits), not the number of keys: a longer length writes the header,
    every key, and then panics at the root; a shorter one writes a header that is too large for the keys written.
  - The wide-length (`>= 2^32`) path can never finish with a real tree: it allocates 0x80 bytes, streams the keys
    into the compound with a u32 counter, and ends in the root "unwrap on None" panic (the counter overflow arm
    needs 2^32 keys and is unreachable). `Compound::end` is therefore only reached with the direct mark.
  - Keys are read in place: the key pointer is `node + 8 + 4*idx`, so unused key slots (garbage) are returned when
    a node length is wrong; the parent index is read from the child, not tracked.
  - Layout b direct writers (0x25e9c70, 0x3d517e0, 0x57d00b0) are separate, longer functions; their growth arm
    is not reached (see Limits).
- Limits:
  - The output Vec reserve is a contract stub (capacity becomes `len + additional`); `finish_grow`, `memcpy`,
    `malloc` and `sdallocx` are contract stubs. Layout b direct cases keep the output Vec large enough, so the
    inlined growth arm of the layout-b writers is not modelled.
  - Unrolled descents (`height >= 8`) and the counter-overflow compare need trees with 2^32 keys or height 8 and are
    not reached; their bytes are not claimed.
  - Keys are `u32`; the `0xcf` (u64) arm of the shared unsigned writer is not reachable from these bodies.
  - The element order of an invalid (unsorted) tree is the structural order; the tool does not claim anything
    about how the set was built.
- Next question: the 727-byte and 850-byte `_ExtStruct` bodies of the earlier family scan (0x226c320/0x41a5a00/
  0x41a70c0/0x52f0c10 and 0x226d4c0/0x226ff00/0x419dee0/0x41a6360/0x52f2d00/0x52f81d0), which likely wrap other
  key/value shapes over the same B-tree iterators, and the sibling `Iter::next` at 0x2388790.
