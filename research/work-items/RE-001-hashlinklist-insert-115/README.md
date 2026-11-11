# RE-001: HashLinkListRep slot-0x08 insert (node #115)

## Task and bounded question

Task: RE-001. Bounded question: how does HashLinkListRep's slot-0x08
method insert one key record — decoding its key, running the transform
chain, hashing to a bucket, and splicing it into the bucket's ordered
chain, with sub-index conversion and the bucket-too-full log?

Artifact: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json). All evidence below is bound to that digest.

## Windows

| window | FDE | file |
|---|---|---|
| host (slot 0x08) | 0x605f700..0x605fe21 | host-605f700.objdump.txt |
| host cleanup landing pad | 0x605f6d6..0x605f700 | host-cleanup-605f6d6.objdump.txt |
| rep ctor (factory slot 0x98) | 0x605eb40..0x605ec19 | ctor-605eb40.objdump.txt |
| rep dtor (slot 0x00) | 0x605ea00..0x605ea23 | dtor-605ea00.objdump.txt |
| varint32 decoder | 0x61bd4f0..0x61bd53b | varint32-61bd4f0.objdump.txt |
| canonical transform | 0x5e9af30..0x5e9b142 | transform-5e9af30.objdump.txt |
| 64-bit hash | 0x61c38a0..0x61c3bb9 | wyhash-61c38a0.objdump.txt |
| hex encoder | 0x61c7e30..0x61c7fb6 | hex-encode-61c7e30.objdump.txt |
| index builder | 0x605f290..0x605f33a | index-builder-605f290.objdump.txt |
| index insert | 0x605f340..0x605f6d5 | index-insert-605f340.objdump.txt |
| log gate | 0x5fcef60..0x5fcf043 | log-gate-5fcef60.objdump.txt |

Excerpts were produced with, e.g.:

```
objdump -d --start-address=0x605f700 --stop-address=0x605fe21 work/hl-node-115.bin
```

Mnemonics such as `endbr64` are genuine instructions present in the
target binary, not placeholders. The excerpts are verbatim objdump output,
whole-function. `export_excerpts.py` (committed here) regenerates them and
`frames.txt` from the binary.

## Claim status

### Observations (read directly from the disassembly)

- The host is HashLinkListRep's vtable slot 0x08: the RELATIVE entry at
  0x64d2170 (vtable 0x64d2168, typeinfo
  `*N7rocksdb12_GLOBAL__N_115HashLinkListRepE`) holds 0x605f700. It has
  no direct call site in `.text`; it is reached only through the vtable.
- Record layout: `{next (+0x00), varint32 key-length + key bytes (+0x08)}`.
- Key-length decode: a single-byte fast path when the byte at arg2+8 has
  its high bit clear; otherwise the varint32 decoder 0x61bd4f0 over
  arg2+8..arg2+0xd. On decoder failure the out slot (pre-zeroed) leaves
  `(ptr 0, len 0)`.
- The host unrolls 13 transform-chain hops: it checks each node's vtable
  slot 0x98 against the canonical 0x5e9af30 and calls the first differing
  slot with the pair `(ptr, len - 8*(k+1))`; if all 13 match it calls the
  13th node's slot with `(ptr, len - 104)`. The canonical callee
  0x5e9af30 advances one node and repeats with len - 8 per hop (up to 9
  hops per call); the only vtable with slot 0x98 equal to 0x5e9af30 is
  InternalKeySliceTransform (vtable 0x64d3bc0, typeinfo
  `N7rocksdb25InternalKeySliceTransformE`), confirmed by the RELATIVE
  entry at 0x64d3c58 and the GOT self-reference at 0x64ed690.
- Bucket index: `(bucket_count * hash64(transformed key)) >> 64`, where
  bucket count is `*(this+0x10)` and the bucket array is `*(this+0x18)`.
- Bucket insert, ordered by the key object's slot-0x10 comparator
  against the DECODED key: an empty bucket stores the record as a bare
  head; a second insert wraps the head in a 0x10-byte count node (count
  1); a head whose `*(node) == node` is a sub-index node and the key goes
  into its embedded 0x38-byte index via 0x605f340; otherwise the count
  increments, the chain is walked and the record is spliced before the
  first node comparing `>= 0`, or at the end.
- Thresholds run on the pre-insert count: if `*(this+0x40) > 0` and the
  count equals `*(this+0x40)`, the log path runs (hex-encode the decoded
  key with flag 1, UPPERCASE, and log via 0x5fcef60 with
  `HashLinkedList bucket %zu has more than %d entries. Key to insert: %s`
  at 0x9638e8); if the count equals `*(this+0x20)`, the convert path
  runs (allocate a 0x48-byte block, build the index at block+0x10 via
  0x605f290 with count 0xc and divisor 4, re-insert every chain node's
  key and the new key via 0x605f340, store the block as the bucket head).
- The landing-pad cleanup 0x605f6d6..0x605f700 disposes the hex string and
  calls `_Unwind_Resume`; the host tail-jumps there from 0x605fe1c.
- The ctor 0x605eb40 is HashLinkListRepFactory slot 0x98 (RELATIVE at
  0x64d22c8, factory vtable 0x64d2230, typeinfo
  `*N7rocksdb12_GLOBAL__N_122HashLinkListRepFactoryE`). It installs
  vtable 0x64d2168, sets `+0x08` = allocator (3rd arg), `+0x10` = bucket
  count (config `+0x20`), `+0x18` = bucket array allocated `count*8`
  and zeroed, `+0x20` = `max(config+0x28, 3)`, `+0x28` = chain head
  (4th arg), `+0x30` = key object (2nd arg), `+0x38` = 5th arg,
  `+0x40` = config `+0x38` dword (log threshold), `+0x44` = config
  `+0x3c` byte. It has no direct call site; it is reached through the
  factory's slot-0x98 virtual. Factory Name literal at 0x43a3e1:
  `HashLinkListRepFactory`; NickName literal at 0x4394cc:
  `hash_linkedlist`.
- The dtor 0x605ea00 is HashLinkListRep slot 0x00 (RELATIVE at
  0x64d2168).
- The 64-bit hash 0x61c38a0 is a mum-mixing hash: seed
  `len * 0x9E3779B185EBCA87`, short paths for lengths 0-16, lane-pair
  accumulation for 17-128, and the shared finalizer
  `y = x ^ (x >> 37); z = y * 0x165667B19E3779F9; return z ^ (z >> 32)`.
  Lengths above 128 jump to helpers 0x61c2890 (len > 0xf0) and
  0x61c3230 (0x80 < len <= 0xf0), outside the modeled FDE.
- The hex encoder 0x61c7e30: flag 0 raw-copies the slice bytes, flag 1
  renders each byte as two UPPERCASE hex digits.
- The varint32 decoder 0x61bd4f0: reads bytes while the high bit is set,
  accumulates 7 bits per byte shifted by 7; fails (returns 0, leaves the
  out slot untouched) if the pointer reaches the limit or the shift
  passes 28.

### Inferences

- Each canonical transform hop pre-strips 8 from the length: the chain is
  the InternalKeySliceTransform chain, so each hop accounts for one 8-byte
  internal-key trailer. The host's 13-hop unrolling and the callee's
  9-hop walk are the same walk, split for inlining.
- The `0x38`-byte sub-index's rehash/growth internals are abstracted in
  the model as an ordered record list preserving the observable
  contract (ordered insertion by the comparator).
- The host's return value is not read by any caller in the binary and is
  not modeled.

### Unknowns

- The concrete key object passed as the ctor's 2nd arg (its slot-0x08 /
  slot-0x10 comparator implementations).
- The concrete terminal (non-canonical) transform at the end of the
  `*(this+0x28)` chain, and which caller builds the chain the factory
  ctor receives as its 4th arg.
- Who calls the factory's slot 0x98 (the rep ctor has no direct call
  site; it is reached only through the factory vtable).
- The hash helpers 0x61c2890 / 0x61c3230 for inputs longer than 128 bytes.
- The rep's slot-0x98 method 0x605ec20 and the other unpinned vtable
  slots.

## Relationship to other PRs

- The index builder (0x605f290), index insert (0x605f340) and log gate
  (0x5fcef60) excerpts and their records are re-shipped byte-identical
  from open PR #3575 (RE-001 slot-0x90 index rebuild, same vtable, same
  helpers). The hex-encode excerpt is re-shipped byte-identical from
  open PR #3561.
- The host 0x605f700 is the slot-0x08 sibling of #3575's slot-0x90 host
  0x605feb0; the two hosts share the index builder, index insert and log
  gate, but the insert host's decode / transform-chain / hash / splice /
  convert behavior is new here.

## Model and tests

- `tools/hashlinklist_insert_115.py`: `hash64`, `encode_varint32` /
  `decode_varint32`, `hex_encode`, `run_transform_chain`,
  `identity_transform`, `compare_records`, `Record`, `CountNode`,
  `IndexNode`, `HashLinkListRep`. The model is validated by
  `tests/test_hashlinklist_insert_115.py` (53 tests): varint round-trip
  and failure modes, hash vectors against the documented length paths,
  transform-chain unrolling, bucket insert ordering, count-node wrap,
  sub-index conversion at the threshold, the log threshold (including
  the log's re-decode and hex rendering), and the ctor's field layout.
- Assumptions are listed in the model docstring and in
  `records.json` (`assumptions`).

## Verification

Run from the repository root:

```
python3 research/work-items/RE-001-hashlinklist-insert-115/verify.py
```

Checks: binary SHA-256 against provenance/artifacts.json; MANIFEST.sha256
entries; excerpt regeneration byte-for-byte; sampled instructions against
fresh objdump and the raw binary (fixed samples plus 3 seeded random gate
spots); frames.txt rows against a fresh objdump frames dump; the caller
census reproduces records.json (all 11 targets, 302 sites); relocations
re-derive from .rela.dyn; vtables re-derive; literals re-read; the model
tests pass under pytest.

`gen_records.py` regenerates records.json, callers.tsv,
relocations.txt and vtables.tsv from the binary. `census.py` reproduces
the caller census. The census re-verifies every call/tail-jump site in
objdump output of its containing FDE.
