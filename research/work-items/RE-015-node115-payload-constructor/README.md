# RE-015 — node 115 payload constructor 0x4741180: it consumes the 0x50-byte source struct and builds the 0x68-byte payload that the wrap ctor moves into a refcounted heap object

Question (one of the open edges carried by the entry-tag-consumers
packet, RE-015-node115-entry-tag-consumers / #2696):

> The payload ctor's body (0x4741180, 1769 bytes) — what does it
> build, field by field, from which inputs, and where does the
> constructed payload go?

Answer, in one line: **the ctor consumes a 0x50-byte source struct
(a head word plus three Vecs) and writes a 0x68-byte payload into
its caller's stack temp: a 0x40-byte head struct assembled from
the head word, a mapped copy of Vec A and per-element inserts
from Vec C (sorted in place first, terminated by a first-word-6
element), a 0x18-byte tail built from the Vec B descriptor, and
the caller's own `rdx`/`rcx` arguments stored verbatim. Its sole
caller, the refcount wrap ctor, then copies the payload into a
0x78-byte refcounted heap object at +0x10 and returns a
0x18-byte node pointing at it.**

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| payload ctor | `0x4741180..0x4741869` | 1769 | `8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a` |
| refcount wrap ctor | `0x4742470..0x4742595` | 293 | `fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c` |

Both body hashes are the same ones the entry-tag-consumers packet
(#2696) pins — the payload ctor there as a boundary (head loads
and the 0x40 record stride only), the wrap ctor as an owner. This
packet traces the payload ctor's full body and the wrap ctor's
post-return storage.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| collect from Vec B | `0x4747a70..0x4747b8c` | `94e2a7361dea19622e98cd267c3079c6f5ef77aaf99c24a6af8c1692a8a1a734` |
| map Vec A | `0x4749d80..0x4749f6e` | `013503c907293d54e1826ea124ba61578b152e6b9ae6abb2655e19a8b0d714e1` |
| map nested Vec | `0x4749f70..0x474a15e` | `ea0826a03cce2cdafa2284acb2eb19257ce802723a71087246eb6ee88717597c` |
| insert into head | `0x4741960..0x4742124` | `19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d` |
| small sort | `0x474ee70..0x474ef61` | `c10705ca00e108908e051353b7469c2317002ed94d09b823f0443c3ed1a65fa1` |
| large sort (slot `0x64eaf68`) | `0x47483e0..0x47484fb` | `12c45f1ed09a4c81a65e8e496ab9e94a3b96ce60bde0aef67e60bd5dc02cb1f1` |
| drop Vec C snapshot | `0x4753770..0x4753864` | `95719dc118a1c123f82dd721aeba0f0488383549aa9e0cedeb045c851c246e98` |
| build Vec B tail | `0x47534b0..0x47536bf` | `6b363d437328781c2760591acf6c594fc661ac13daa401668d858bf1892117b6` |
| collection drop | `0x4742810..0x474284b` | `c3e2db799db8445cc9b10c4d52f66d1d74d14c401d723c1031396be43445ff01` |
| registrar | `0x474f6a0..0x474f7ff` | `a26fb8c2033f2f6c6242755b86e5377a13bce19b1459d1761ddf9b56c8132c1e` |

The two map helpers are the same size (494 bytes) and are called
with identically shaped iterator/context blocks, but their body
hashes differ; this packet does not claim they are clones.

## Calling convention and source layout

The ctor's sole direct call site in the binary is `0x474248e`
inside the wrap ctor (whole-.text E8 census). The wrap ctor has
no direct call sites at all; it is reached only through slot
`0x64eaf70` (RELATIVE addend `0x4742470`) from the registrar, as
#2696 established. The wrap ctor passes:

- `rdi` = a 0x68-byte stack temp in its own frame (`rsp+0x10`) —
  the payload destination;
- `rsi` = its own incoming pointer argument, unchanged — the
  0x50-byte source struct;
- `rdx` = 1 (`0x4742486`);
- `rcx` = `0x6494c78`, a `.data.rel.ro` table pointer (`0x474247f` lea).

Source struct (0x50 bytes at `rsi`):

| Offset | Field |
| ---: | --- |
| +0x00 | head scalar |
| +0x08 | Vec A capacity |
| +0x10 | Vec A pointer — 0x18-byte elements |
| +0x18 | Vec A length |
| +0x20 | Vec B capacity |
| +0x28 | Vec B pointer — 0x40-byte elements |
| +0x30 | Vec B length |
| +0x38 | Vec C capacity |
| +0x40 | Vec C pointer — 0x40-byte elements |
| +0x48 | Vec C length |

Element strides are read off the end-pointer arithmetic in the
body: Vec A and the nested Vecs use `len * 0x18` (via
`(len + len*2) * 8`), Vecs B and C use `len << 6`.

## Construction, phase by phase

1. **Collect.** The ctor snapshots the Vec B and Vec C headers,
   builds an iterator `{ptr_B, end_B}` over Vec B and calls
   `0x4747a70` with a destination at `[rsp+0x1b0]` — a lookup
   collection built from Vec B's elements (body = boundary).
2. **Map Vec A, assemble head struct S.** An iterator
   `{ptr_A, end_A, &collection}` is built; when `len_A > 0` a
   `len_A * 8` buffer is allocated through slot `0x64df480`
   (allocation failure goes to the alloc-error slot `0x64df498`
   and `ud2`). Helper `0x4749d80` (boundary) fills the buffer,
   updating a slot word initialised to 0. S is assembled at
   `[rsp+0x108]`:

   | S offset | Value |
   | ---: | --- |
   | +0x00 | source +0x00 |
   | +0x08 | Vec A length |
   | +0x10 | mapped Vec A buffer |
   | +0x18 | helper-updated slot word |
   | +0x20 | static table pointer `0x450150` |
   | +0x28 | 0 |
   | +0x30 | 0 |
   | +0x38 | 0 |

   The last four words are one 32-byte block copied from
   `0x6494c58`; after RELATIVE relocation only the first word is
   nonzero (`0x450150`, a `.rodata` byte-table address).
3. **Sort and walk Vec C.** When `len_C >= 2`, Vec C's buffer is
   sorted **in place**: below 21 elements by a direct call to
   `0x474ee70` (`0x4741715`), at 21 or more through slot
   `0x64eaf68` → `0x47483e0` (with a flag byte set on that path).
   The walk then iterates Vec C at 0x40 stride from `ptr_C` to
   `end_C`:
   - an element whose first word is **6 terminates the walk**
     (`cmp $6` at `0x47413b6` jumps to the post-loop block) —
     later elements are not processed;
   - any other element is copied verbatim (0x40 bytes) to a
     stack record; its nested Vec `{cap +0x20, ptr +0x28,
     len +0x30}` of 0x18-byte elements is mapped through
     `0x4749f70` into a fresh `len * 8` buffer; and the insert
     helper `0x4741960` is called with `&S`, the element's
     +0x10 and +0x18 words, the mapped nested block, the
     element's +0x38 low byte and its first word;
   - per element, the copied record's inner Vec buffer, each
     nested element's inner Vec buffer, and the nested Vec
     buffer itself are freed through the dealloc slot
     `0x64df4a0` (→ `0x635de30`).
4. **Tail and final write.** The Vec C header snapshot is passed
   to drop helper `0x4753770`; the collection's buffer is freed
   if its capacity word (`[rsp+0x1b8]`) is nonzero; helper
   `0x47534b0` builds a 0x18-byte tail T from a Vec B descriptor
   `{ptr_B, ptr_B, cap_B, end_B}`. The payload is then written
   to the out pointer in one block:

   | Payload offset | Value |
   | ---: | --- |
   | +0x00..0x40 | head struct S |
   | +0x40..0x58 | tail T |
   | +0x58 | the `rdx` argument verbatim (saved at entry) |
   | +0x60 | the `rcx` argument verbatim (saved at entry) |

5. **Source consumption.** On the success path the ctor frees
   every Vec A element's inner Vec buffer (`{cap +0, ptr +8}`
   per 0x18-byte element) and then Vec A's own buffer if
   `cap_A != 0` (size `cap_A * 0x18`). No free of the Vec B or
   Vec C buffers appears in the body after their uses; the
   recorded disposals are the Vec C header-snapshot drop (phase
   4) and the Vec B descriptor's consumption by the tail build.

## Where the payload goes

Immediately after the ctor returns, the wrap ctor — the only
code that touches the stack temp — prefixes refcount words
`{1, 1}`, allocates 0x78 bytes (slot `0x64df480`), and copies
the whole 0x78-byte block into the heap object, so the payload
lives at **heap+0x10**. It then allocates a 0x18-byte node whose
+0x10 word is that payload pointer (its +0x00 pair is the same
refcount header) and returns the node pointer in `rax`. From
there the chain is the one #2696 traced: the registrar receives
the node pointer through slot `0x64eaf70`, stores a derived word
in the global cell behind slot `0x64eaf08` (→ `0x64ffef8`), and
the consumer's wrapper stores the returned pointer at its out
object +0x50. Who reads the registered object back afterwards
remains an open edge from #2696 and is **not** part of this
packet.

## Limits

- The helper bodies in the Boundaries table are hash-pinned
  only: what the collection at `[rsp+0x1b0]` contains, how the
  two map helpers index it (and what the slot word at S+0x18
  counts), how the insert helper mutates S, and what the tail
  build computes from the Vec B descriptor are not traced here.
- The sort comparator's closure environment is a single stack
  byte at `[rsp+0xf]` reached through `[rsp+0x40]`; the body
  contains no separate store to that byte, and this packet does
  not characterise the comparator.
- Landing-pad cleanup paths are pinned by the frame records
  only; the exact LSDA protection ranges are not decoded.

## Next question

What does the insert helper `0x4741960` (1,988 bytes, with two
further call sites inside its own body) do to head struct S for
each Vec C element — which S fields does it read and write, and
how do the element's first word, its +0x38 low byte and the
mapped nested block decide the outcome?

## Verification

- `tools/payload_ctor_static.py` re-derives every pin above from
  the authenticated binary: FDE extents and body hashes for both
  owners and all ten boundaries, the whole-.text direct-call
  census, all slot bindings via `.rela.dyn`, the static block's
  relocated words, and byte pins for the phase gates, the
  terminator comparison, the final stores and the wrap ctor's
  storage steps.
- `tests/test_payload_ctor_static.py`: shape, slot bindings,
  census, layouts, five one-byte counterfactuals (terminator
  comparison, final out store, ctor call target, Vec C length
  gate, static-block load), a generate round-trip, and equality
  with the committed `records.json`.

Made via @slopdotcash
Authored with AI assistance (Meta Muse Spark)
