# RE-015 — node 115 insert helper 0x4741960: it splits each Vec C element's key on the first "::" and descends a hash-map tree rooted at head struct S, storing a fresh child S per segment

Question (carried by the payload-constructor packet
RE-015-node115-payload-constructor / #2736):

> The insert helper `0x4741960` (1,988 bytes, with two further
> call sites inside its own body) — for each Vec C element, how
> does it mutate head struct S? Which fields of S does it read
> and write, and how do the element's first word, its +0x38 low
> byte and the mapped nested block decide the outcome?

Answer, in one line: **the helper treats S as the root of a
"::"-keyed tree. It splits the element's key (pointer/length
from the element's +0x10/+0x18 words) on the first "::"; when
S's embedded map is populated (S+0x38 nonzero) it probes that
map with an FNV-1a hash of the head segment and recurses into
the matching bucket's child S with the tail; otherwise it
inserts the head segment into S's map with a fresh child S as
the value — recursing on the tail first when the tail is
nonempty, and at a leaf building the child from the element's
first word (stored at child S+0x00) and the mapped nested block
(stored at child S+0x08..0x20), appending S's own mapped array
into that block first when the element's +0x38 low byte is
nonzero. The helper body stores nothing to S directly; S
changes only through the map-insert call on &S+0x20 and through
recursion into child S values stored in the map's buckets.**

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| insert helper | `0x4741960..0x4742124` | 1988 | `19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d` |

The body hash is the same one the payload-constructor packet
(#2736) pins for this helper as a boundary.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| payload ctor (sole external caller) | `0x4741180..0x4741869` | `8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a` |
| searcher next | `0x4740170..0x474031f` | `61665365392f79cf0ccb5af674672a22b9e9777b3bcc4bad44e51ee6d033d9d1` |
| map insert | `0x474b620..0x474ba5d` | `f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658` |
| displaced-record drop | `0x4742960..0x4742a93` | `1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1` |
| mapped-block grow | `0x474e640..0x474e6bf` | `43935a1cdae8c5854d4a239f0992801b4808673b0bb5ff24da951160a868e8bf` |
| landing-pad cleanup drop | `0x4740a30..0x4740a5d` | `b9665ed96a0cac53d797b8f522125f800644ca4b34fdb8928466bee2d5811c09` |

Slot bindings (`.rela.dyn`): searcher build `0x64dfcb8` →
`0x167ff90`; slice-error `0x64df670` → `0x16806c0`; panic
`0x64df520` → `0x1681da0`; alloc `0x64df480` → `0x6355830`;
dealloc `0x64df4a0` → `0x635de30`; alloc-error `0x64df498` →
`0x141e264`; the three str-error statics `0x6494ca8` /
`0x6494cc0` / `0x6494cd8` all → `0x44dc38`. GLOB_DAT slots:
`0x64df9f8` = `bcmp`, `0x64df508` = `memcpy`.

## Call sites and arguments

The whole-.text direct-call census for `0x4741960` is exactly
three sites: the payload ctor's call at `0x47414e0` and the two
self-calls at `0x4741ccf` and `0x4741e86`. The ctor (its element
record sits at `[rsp+0x40]` in the ctor frame) passes:

- `rdi` = `&S` (S is at `[rsp+0x108]` in the ctor frame);
- `rsi` = the element's +0x10 word — a key byte pointer
  (`[rsp+0x50]` of the record);
- `rdx` = the element's +0x18 word — the key byte length
  (`[rsp+0x58]`);
- `rcx` = a pointer to the mapped nested block built by
  `0x4749f70`: `{capacity words +0x00, buffer +0x08, length
  +0x10}`, 0x18 bytes of u64 words;
- `r8b` = the element's +0x38 low byte (`[rsp+0x78]`);
- `r9` = the element's first word (ctor's `r13`).

## What it reads from S

| S offset | Use |
| ---: | --- |
| +0x00 | copied into a tail-built child's S+0x00 |
| +0x10 | mapped array buffer: copied into a tail-built child; appended into the mapped block on the leaf path |
| +0x18 | mapped array word count: a tail-built child's S+0x08 and S+0x18, the array copy length, the leaf append count |
| +0x20 | map control pointer (probe); the map passed to the insert call |
| +0x28 | map bucket mask (probe) |
| +0x38 | map-populated dispatch word: nonzero → probe the map; zero → skip the probe |

No instruction in the body stores to S. Writes to S happen
only inside the map-insert callee `0x474b620` (the map words at
S+0x20..0x40 and its bucket allocation) and inside recursive
calls on child S values stored in buckets (bucket+0x18) — never
into the 0x40 bytes of the S passed in.

## Behaviour, phase by phase

1. **Split.** A searcher state is built at `[rsp+0x90]` through
   slot `0x64dfcb8` from (key ptr, key len, needle `0x7df837`,
   needle length 2); the needle bytes are `::`. One step of
   `0x4740170` returns a tag dword at `[rsp+0x100]`: 1 with the
   match index at `[rsp+0x108]`, or not-1 when there is no
   match. With a match, head = `key[..idx]`, tail =
   `key[idx+2..]`; without one, head = the whole key and the
   tail is empty. The slicing is guarded by the compiled-in
   char-boundary checks (a byte in `0x80..0xbf` at a slice point
   is rejected): failure leaves through the noreturn slice-error
   call (slot `0x64df670`, statics at `0x6494ca8`/`0x6494cd8`),
   and an out-of-range split index leaves through the panic call
   (slot `0x64df520`, static `0x6494cc0`). With an empty tail the
   saved tail pointer is inert (the raw `idx+2` offset, or 1 on
   the no-match path): it is only ever used with length 0.
2. **Probe (only when S+0x38 != 0).** The head segment is hashed
   with FNV-1a (basis `0xcbf29ce484222325`, prime
   `0x100000001b3`) over its bytes plus a final `0xff` byte; an
   empty head uses the constant `0xaf64724c8602eb6e`, which is
   exactly that hash of `[0xff]` (verified arithmetically). The
   table at S+0x20 (control pointer) / S+0x28 (bucket mask) is
   probed hashbrown-style: the control-byte pattern is the
   hash's top 7 bits (`hash >> 0x39`), control bytes are scanned
   in 16-byte groups, and buckets are the 0x58-byte records
   located before the control bytes (key record 0x18 bytes +
   child S 0x40 bytes). A candidate is a hit only when the key
   length at bucket+0x10 equals the head length and `bcmp`
   (slot `0x64df9f8`) of the stored key pointer at bucket+0x08
   against the head bytes returns 0. A group containing an
   empty control byte (`0xff`) with no hit ends the probe as a
   miss.
3. **Hit.** The helper recurses (self-call `0x4741ccf`) into
   the bucket's child S (bucket+0x18) with the tail pointer and
   length, a verbatim 0x18-byte copy of the mapped block, the
   flag byte and the first word, then returns. Nothing is
   inserted at this level.
4. **Miss with a nonempty tail.** A child S is assembled on the
   stack: +0x00 = S+0x00, +0x08 = S+0x18, +0x10 = a fresh
   allocated copy of S's mapped array (S+0x18 words copied from
   the S+0x10 buffer through the alloc/`memcpy` slots; when
   S+0x18 is 0 the word 8 stands in as the buffer word and
   nothing is allocated), +0x18 = S+0x18, +0x20..0x40 = the
   static empty-map block at `0x6494c58` (relocated words
   `{0x450150, 0, 0, 0}`). The helper recurses on the tail into
   that child (self-call `0x4741e86`, with a copy of the mapped
   block), and the possibly mutated child becomes the value for
   the head segment in phase 6.
5. **Leaf (empty tail).** The value is a fresh 0x40-byte S:
   +0x00 = the element's **first word**, +0x08..0x20 = the
   **mapped nested block**, +0x20..0x40 = the static empty-map
   block. Before the block is stored, when the element's
   **+0x38 low byte is nonzero**, S's mapped array (S+0x18 words
   from S+0x10) is appended into the block's buffer: if the
   count exceeds `block capacity − block length` the block is
   grown through `0x474e640` (element size 8), the words are
   copied to `block buffer + block length * 8`, and the new
   length is stored back at block+0x10. With flag byte 0 the
   block is stored exactly as the map helper produced it. The
   first word and the flag byte are otherwise only forwarded,
   unchanged, through the recursions; neither steers the split,
   the probe or the insert key.
6. **Insert.** The head segment's bytes are copied into a fresh
   allocation (length 0 keeps the sentinel pointer 1, no
   allocation), a key descriptor `{len, ptr, len}` is built,
   and `0x474b620` is called with `&S+0x20`, the descriptor and
   the value block. If the result dword at `[rsp+0x100]` is 6
   the helper returns at once. Otherwise the result carries a
   displaced record: its array (count at result+0x08, buffer at
   result+0x10) is freed through the dealloc slot with size
   `count * 8`, and the sub-record at result+0x20 is dropped by
   `0x4742960`, before returning.

## Limits

- The boundary bodies are hash-pinned only: how the searcher
  state machine steps, how `0x474b620` grows the table and what
  its result variants are beyond the dword-6 test and the
  displaced-record cleanup, how `0x474e640` reserves capacity,
  and what `0x4742960` drops field by field are not traced here.
- The bucket key record's first word (bucket+0x00) is never read
  by the probe; at insert time the descriptor's first and third
  words are both the head length, and this packet records the
  layout mechanically without naming the key type.
- Landing-pad cleanup paths are pinned by the frame records
  only; the exact LSDA protection ranges are not decoded.

## Next question

What does the map insert `0x474b620` (1,085 bytes) do to the
map words at S+0x20..0x40 — how does it grow the table, where
does it write the `{len, ptr, len}` key record and the 0x40-byte
value inside a 0x58-byte bucket, and what distinguishes the
result variant whose dword is 6 from the one that hands back a
displaced record for cleanup?

## Verification

- `tools/insert_helper_static.py` re-derives every pin above
  from the authenticated binary: FDE extents and body hashes
  for the owner and all six boundaries, the whole-.text
  direct-call census, all slot bindings via `.rela.dyn` and
  `.dynsym`, the needle bytes, the static block's relocated
  words, the empty-head FNV constant, and byte pins for the
  split, the dispatch, the hash, the probe loads, both
  self-calls, the flag test, the insert and its result test.
- `tests/test_insert_helper_static.py`: shape, slot bindings,
  census, layouts, five one-byte counterfactuals (FNV basis,
  searcher result tag, found-path self-call, insert result tag,
  S+0x38 dispatch), a generate round-trip, and equality with
  the committed `records.json`.

Made via @slopdotcash
Authored with AI assistance (Meta Muse Spark)
