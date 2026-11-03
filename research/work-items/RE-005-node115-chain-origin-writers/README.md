# RE-005: node 115 chain origin — where the value's `chain` string comes from, and the registration boundary above Z

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for both trails below, all re-derived
  from the pinned target bytes by the checker; **unresolved** for
  every naming or semantic claim listed under the boundary.

## The bounded question

The tag-writer packet (RE-005-node115-rmp-signable-tag-writers)
established that the apply function `0x564cce0` writes the chain-class
byte at record +0x90 after reading the value's `chain` field through
the getter `0x4e4ca30`, and that the byte B4 reads at arg2 +0xbd5 is
staged into Z's (`0x2af77f0`) own object by a 0xbd8-byte memcpy from
the object itself. It left two questions open. (1) Where does the
value's `chain` string originate inside the inputs of the value
producer `0x165de90` / `0x165dfb0` — who writes the map field the
apply function reads? (2) Which path first writes the +0xbd5 field
of Z's input object, given that Z has no direct `.text` call site?
This packet answers both, one level up.

## Why this item

The operator action is answering the two questions the tag-writer
packet explicitly leaves open. The basis for the expected behaviour
is the serializer's own contract (the chain-top packet's claim): its
emitted byte is 0x61 iff the source byte is 3, else 0x62, and the
class byte is decided by the `chain` string, so a reconstruction of
the signing payload must know where that string can come from. The
loss when it is wrong is a payload whose tag byte differs from the
node's — a signature over different bytes — or a reconstruction that
invents a producer for the `chain` field that the binary does not
have. Independence by repro case: the other open RE-005 packets
cover the varint size-state (#2257), the u64 reader state (#2300),
the `rmp_signable` .rodata census (#2311), the serializer (#2399),
the caller tags (#2419), the varint readers (#2412, #2422), the
field1-5 caller arguments (#2433), the chain top (#2432), the tag
sources (#2444) and the tag writers (#2466); none traces the value
producer's inputs or Z's reference structure. The producer
(`0x165de90`, slot-bound in #2466's records as a boundary), the
getter (`0x4e4ca30`, likewise), B2, the apply function, the spec
builder and Z are referenced here from those packets, not re-owned;
the new owners are the producer wrapper and core as traced bodies,
the getter as a traced body, and the TLS registry accessor.

## Exact scope

| role | FDE half-open range | bytes | body SHA-256 |
| --- | --- | ---: | --- |
| value_producer | `0x165de90..0x165dfaa` | 282 | `74c6473d58677655e2e99becf0abe03d3a1f31bcf251ad92e390520ad846aeae` |
| value_producer_core | `0x165dfb0..0x165e513` | 1,379 | `a074b2b22ad5683f183a1e2ea1516c71da55af8b3d9683b5d489aa7f79cf74a2` |
| field_getter | `0x4e4ca30..0x4e4cba7` | 375 | `ada0f99b7af4158c85795c1ea74fd28fb09de9837fb6ffad0063d523839de8a0` |
| tls_registry | `0x1668ce0..0x1668d1c` | 60 | `583ede91b19c87963042232b1108955f7392fc511c6bbbbed46a44738844d0bd` |

Referenced, not owned (owners of the tag-source/tag-writer packets
#2444/#2466; only the listed instructions are re-pinned here): B2
`0x2ae41e0..0x2ae6d66`, the apply function `0x564cce0..0x564cf36`,
the spec builder `0x564d700..0x564df8c`, and Z
`0x2af77f0..0x2af8bd3`. All other helpers are hash-pinned boundaries
in `records.json` (registry worker, merge builder, file reader,
container init/dtor, spec-copy/context/temp destructors, predicate
bit test, three record fixups, value converter, key hash, TLS init
helpers, panic helpers, and the two lu.rs FDEs that reference the
registration location).

## Trail 1: the `chain` string is input data at the worker/builder boundary

The producer's wiring, all slot-bound or direct as pinned:

- The value producer `0x165de90` has **no direct call site**; it is
  reached only through slot `0x64e1da8`, called at exactly two sites:
  B2 `0x2ae430b` and the buffer converter `0x2b7b6b8` (the slot-call
  census is part of the evidence). Both callers hand it
  (out, spec), where the spec is the spec builder's 0x250-byte out
  struct: in B2 the record sits at rsp+0xd0, the constructor
  (slot `0x64e1d08`) builds it from the frame key `hl-node`, the spec
  builder (slot `0x64e73c0`) writes its out over the key slot at
  rsp+0x380, the producer is called with out = rsp+0x50 and
  spec = rsp+0x380, the 0x50-byte value is copied back over
  rsp+0x380, and the apply function (slot `0x64e73c8`) runs over
  (record, value copy).
- The wrapper `0x165de90` copies the spec (0x250 bytes, memcpy
  through the bound slot `0x64df508`) onto its frame at rsp+0x28,
  initialises a container of 0x18-byte elements at rsp+0x8 (slot
  `0x64e1290` → `0x5c9a530`), and calls the core — its **only**
  direct caller in the binary (direct-call census) — with
  (out, frame copy, container). After the core returns it destroys
  the copy (dtor `0x165e570`) and drops the container elements
  through slot `0x64df4a0`.
- Inside the core `0x165dfb0`, no instruction writes any map entry.
  A mov-form store census over the range where r14 holds the spec
  copy finds exactly three stores into it: the loaded-string move
  at +0x38 (length), +0x40 (pointer), +0x48 (capacity)
  (`0x165e212`/`0x165e216`/`0x165e21a`), plus the pinned flag-byte
  or at +0x1ec (`0x165dffe`). Everything else the core does with the
  copy is read it or hand it to a boundary: the predicate bit test
  at &copy+0x1e8 (slot `0x64e1b98`, bits 0x27 and 0x16; on the first
  failure three fixups `0x1635410`/`0x1635ac0`/`0x1635e30` receive
  the copy before the +0x1ec or), one container element naming a
  file whose contents are read (slot `0x64e0938`, result tag 9) and
  converted (slot `0x64dfca8`) into the copy's +0x38 string slot
  when that slot still holds the sentinel, and the two value paths:
  - **Path A** — the registry worker `0x1630c90` (17,970-byte
    boundary) is called with (result, spec copy, ctx, &sentinel+1),
    where the ctx is built from the static template at `0x6407558`
    plus the TLS registry cell's (counter, pointer) pair at
    +0x38/+0x40. When the result head is not the sentinel, out is
    the worker's 0x50-byte result struct copied verbatim
    (`0x165e2ca..0x165e2ee`, head = sentinel+1). The map the getter
    later reads is whatever the worker built.
  - **Path B** — when the result head is the sentinel, the core
    extracts, from the spec copy's +0x190 array pointer and +0x198
    count, each 0x210-byte entry's 16-byte pair at entry +0x180
    into a fresh allocation, takes the TLS registry cell through
    the accessor `0x1668ce0` (its only direct caller is this site,
    `0x165e388`; the 60-byte accessor returns the fs−0x450 cell,
    lazy-initialising through `0x1671e70`), builds a temp header
    from the registry pair and the static template at `0x6406be8`,
    and calls the merge builder `0x1667780` (2,679-byte boundary)
    with (ctx, pairs, count, temp). Out is the ctx header copied
    back (`0x165e3db..0x165e413`). The entry array the pairs come
    from is spec-builder-written: the spec builder's second block
    copy (memcpy through r12 at `0x564de75`, length 0x1b0 to
    out +0xa0) covers +0x190/+0x198.
- The getter `0x4e4ca30` is a pure lookup. It returns 0 when
  [map +0x30] is 0, hashes the key with the state at map +0x38
  (`0x4e52640`), probes the entries at [map +0x18] under the mask
  at [map +0x20], matches a key by length compare and `bcmp`
  (fn pointer loaded from slot `0x64df9f8`), and on a match passes
  the entry's value string ([value +0x8], [value +0x10]) through
  the converter (slot `0x64dfca8` → `0x16815e0`); converter tag 1
  reaches the `unexpected invalid UTF-8 code point` panic (string
  at `0x918811`, via slot `0x64df770`). A store census over its
  body for destinations based on the entries register, the entry
  pointer, or the value-object register finds **zero** hits: the
  getter writes nothing. Apply's read of the field is pinned at
  `0x564ccf7` (name `chain` at `0x92a7be`), `0x564ccfe` (length 5),
  `0x564cd03` (arg1 = the value), `0x564cd06` (the call).

So the `chain` string is not computed by the producer, the wrapper,
or the getter: the value's entries materialise only inside the
registry worker (path A) or the merge builder (path B) — both
hash-pinned boundaries — from inputs this packet pins (the spec
copy, the ctx, the registry cell, and the spec-builder-written
entry array). The string is input data at that named boundary.

## Trail 2: Z is reachable only through its registration record

Z (`0x2af77f0`, #2466's `b4_caller_stager`) stages B4's arg2 by
memcpying 0xbd8 bytes from its own arg1 object to obj +0xca0
(pins at `0x2af7839`, `0x2af7840`, `0x2af784b`, through the bound
memcpy slot `0x64df508`), so the +0xbd5 byte B4 reads is the object's
own byte, copied verbatim; and Z's body contains no occurrence of
the byte sequence `d5 0b 00 00` at all (re-derived here over the
reference body). The question is who calls Z and builds that
object. The reference census is complete and negative:

- Direct call/jump census for `0x2af77f0` over all of `.text`:
  **empty** (as #2466 found).
- Relocation census: exactly **one** reference to Z exists in the
  binary — a type-8 (RELATIVE) relocation whose slot is
  `0x6447268` and whose addend is Z. The raw qword `0x2af77f0`
  occurs exactly once in the whole file: that addend.
- The slot is the second word of a 0x28-byte static record at
  `0x6447260`: {8, Z, `base/src/lu.rs` pointer `0x4326c1`, 14,
  packed line 24 / col 16} — a function pointer paired with its
  source location. The record head and tail words carry no
  relocation; neither the record base (`0x6447260`) nor the slot
  (`0x6447268`) occurs as data anywhere except the relocation
  entry's own offset field, and a RIP-relative candidate census
  over `.text` for Z, the record base, and the slot is **empty**
  for all three.
- The record is one of **447** statics of the same shape
  {8, fn ptr, .rs file, len, line/col} in `.data.rel.ro` (pattern
  census, re-derived by the checker). Six name `base/src/lu.rs`;
  Z's is the line-24 one.
- The record's location field (`0x6447270`) *is* referenced from
  code: eight `lea rdi` sites in FDEs `0x2accee0` (four) and
  `0x2ad0db0` (four) pass it as the &Location argument to the
  bound location panic helpers `0x1681e60` / `0x1681e80` (slots
  `0x64e1368` / `0x64e1360`). Those are panic sites in lu.rs code;
  none of them invokes Z, and no other code references any part
  of the record.

So within this binary Z is reachable only through the registration
record: no traced caller invokes it, and consequently no traced
code path constructs its arg1 object at all. The first writer of
the +0xbd5 field sits above that dispatch — in whatever consumes
the registration — and is not traced code in this binary.

## Boundary

- Trail 1: what the registry worker `0x1630c90` and the merge
  builder `0x1667780` do inside their own bodies — in particular
  where the `chain` entry is first inserted into the value map —
  is inside those hash-pinned boundaries. The three record fixups
  (`0x1635410`, `0x1635ac0`, `0x1635e30`) receive the spec copy on
  the predicate-failure path and are likewise boundaries; anything
  they write happens before the worker/builder run, so it cannot
  change the verdict that entries materialise only in the two
  named helpers. Which of paths A/B a given run takes, and the
  runtime contents of the registry, are execution facts outside
  static evidence.
- Trail 2: the consumer of the 447 registration records is not
  statically reachable from `.text` in this binary (no record base
  is referenced by any instruction, for Z's record or any other).
  Who invokes Z, and what constructs its arg1 object, is
  unresolved above the registration record.
- Semantic names (spec, value, registry, registration record)
  follow the earlier RE-005 packets and the byte-level roles
  proven here; no Rust type names are claimed.

## Validation

- `tools/chain_origin_writers_static.py` regenerates
  `records.json`, `frames.txt`, and the disassembly exports from
  the authenticated artifact and re-derives every byte pin,
  relocation binding, boundary hash, and census above — including
  the core store census, the getter store census, the Z reference
  census, and the 447-record registration census.
- `tests/test_chain_origin_writers_static.py` asserts regeneration
  byte-identity, the trail verdicts, instruction-start validity of
  the eight location lea sites inside their containing FDEs, and
  counterfactual rejection (mutated worker/builder call targets,
  producer slot binding, B2 producer call, core store, getter bcmp
  binding, registration fn word, registration pattern count, and a
  boundary body each rejected with its specific error).
- MANIFEST.sha256 entries are re-validated with `sha256sum -c` and
  with the fixed packet verifier from the verify-packets LFS
  pointer fix (#2347) in an isolated root.

## Next question

Inside the two trail-1 boundaries, which code first inserts the
`chain` entry into the value map: trace the map construction inside
the registry worker `0x1630c90` (path A) or the merge builder
`0x1667780` (path B) — and, for trail 2, which registered function
of the 447 constructs the object Z receives, i.e. identify the
registration consumer's call site that materialises Z's arg1.
