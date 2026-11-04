# RE-015 — node 115 map insert 0x474b620: a hashbrown-style insert that grows on growth-left 0, swaps the value on a hit, and marks a fresh insert with the single qword 6

Question (carried by the insert-helper packet
RE-015-node115-insert-helper):

> What does the map insert `0x474b620` (1,085 bytes) do to the
> map words at S+0x20..0x40 — how does it grow the table, where
> does it write the `{len, ptr, len}` key record and the
> 0x40-byte value inside a 0x58-byte bucket, and what
> distinguishes the result variant whose dword is 6 from the
> one that hands back a displaced record for cleanup?

Answer, in one line: **the insert hashes the key with the same
0xff-terminated FNV-1a the helper's probe uses, grows the
table through `0x4742aa0` when the growth-left word at
map+0x10 is 0, and probes 16-byte control groups; on a hit it
swaps the value in place — the displaced 0x40-byte value is
copied to the caller's out scratch (its own first word is the
dword the caller tests), the incoming key buffer is freed and
no map word changes — while on a miss it writes the key
record at bucket+0x00..0x18 and the value at bucket+0x18..0x58,
sets the slot's control byte and its mirror, bumps the item
count at map+0x18, charges growth-left only for a truly empty
slot, and marks the result with the single qword 6 at
out+0x00, the variant the caller returns on without cleanup.**

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| map insert | `0x474b620..0x474ba5d` | 1085 | `f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658` |

The body hash is the same one the insert-helper packet pins
for this body as a boundary.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| insert helper (sole caller) | `0x4741960..0x4742124` | `19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d` |
| grow / reserve | `0x4742aa0..0x4743347` | `dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67` |
| displaced-record drop | `0x4742960..0x4742a93` | `1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1` |
| value drop (landing pad) | `0x474ac30..0x474ac5d` | `a40c63266a40637f39a94b76a535c5f934ad1679a466075465f8f8871e569c87` |
| next body | `0x474ba60..0x474bcd3` | `4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44` |

Slot bindings (`.rela.dyn`): bcmp `0x64df9f8` (GLOB_DAT,
dynsym 11); dealloc `0x64df4a0` → `0x635de30`; grow function
`0x64eaf78` → `0x4742aa0`; unwind tail `0x64df4c0` →
`0x1680cab`.

## Call sites and arguments

The whole-.text direct-call census for `0x474b620` is exactly
one site: the insert helper's call at `0x4742025`. The helper
passes:

- `rdi` = a 0x48-byte out scratch in its own frame (the
  result; returned in `rax`); the helper tests the dword at
  out+0x00 against 6 (`0x474202a`);
- `rsi` = the map pointer (`&S+0x20`);
- `rdx` = a key descriptor `{len +0x00, byte ptr +0x08,
  len +0x10}` over a fresh copy of the head segment's bytes;
- `rcx` = a pointer to the 0x40-byte new value block (a child
  S built by the helper).

## The map words (rsi = &S+0x20)

| Map offset (S offset) | Use in this body |
| ---: | --- |
| +0x00 (S+0x20) | control-byte base pointer; reloaded after a grow; buckets are the 0x58-byte records located before it |
| +0x08 (S+0x28) | bucket mask; probe indexes and the mirror index are ANDed with it |
| +0x10 (S+0x30) | growth left: tested against 0 before the probe (grow call when 0); decremented only when a fresh insert consumes an empty (0xff) slot |
| +0x18 (S+0x38) | item count: incremented by 1 on every fresh insert (the helper probes only when this word is nonzero) |

## Bucket layout

Buckets are 0x58-byte records located **before** the control
bytes: `bucket(i) = ctrl − (i+1)·0x58`.

| Bucket offset | Field |
| ---: | --- |
| +0x00 | key record word 0 — the descriptor's first word (the head length) |
| +0x08 | key byte pointer (the `bcmp` target on a candidate) |
| +0x10 | key length (compared against the probe key length before `bcmp`) |
| +0x18..0x58 | the 0x40-byte value (the stored child S) |

## Behaviour, phase by phase

1. **Hash.** The descriptor's bytes (ptr at +0x08, length at
   +0x10) are hashed with FNV-1a (basis `0xcbf29ce484222325`,
   prime `0x100000001b3`, 8-byte unrolled main loop plus a
   scalar tail), with a final `0xff` byte folded in — the
   identical hash the helper's probe computes. A zero-length
   key uses the constant `0xaf64724c8602eb6e`, exactly that
   hash of `[0xff]` (verified arithmetically). The
   control-byte pattern is the hash's top 7 bits
   (`hash >> 0x39`).
2. **Grow.** If the word at map+0x10 (growth left) is 0, the
   body calls the grow function through slot `0x64eaf78`
   (→ `0x4742aa0`, boundary) with `(map, 1, map+0x20, 1)` —
   the `map+0x20` argument is one word past the four map
   words — then reloads the control pointer and the mask and
   falls into the probe. This fires both for a never-grown
   empty map (all three trailing words 0) and for a full one.
3. **Probe.** Control bytes are scanned in 16-byte groups
   starting at `hash & mask`, stepping by triangular group
   offsets. Per group, lanes whose control byte equals the
   pattern are candidates: bucket index = `(group + lane) &
   mask`; a candidate is a hit only when bucket+0x10 equals
   the key length and `bcmp` (slot `0x64df9f8`) of the stored
   key pointer at bucket+0x08 against the key bytes returns
   0. Matched-but-rejected lanes are peeled (`mask &=
   mask−1`) and the rest of the group is retried. While
   scanning, the first special control byte (empty `0xff` or
   deleted `0x80`) is tracked for phase 5.
4. **Hit (replace).** The bucket's old value (bucket+0x18,
   0x40 bytes) is copied into the out scratch, the new value
   (the `rcx` argument) is copied into the bucket, and the
   incoming key's buffer is freed through the dealloc slot
   (size = the descriptor's first word) when that word is
   nonzero. The bucket's stored key record is **kept**, and
   **no map word changes** — no counter update, no control
   byte write. The body returns the out pointer. The dword
   the caller tests at out+0x00 is therefore the displaced
   value's own first word, not a synthetic tag: the helper
   returns at once only when that word is 6, and otherwise
   frees the array at out+0x08/+0x10 and drops the
   sub-record at out+0x20 via `0x4742960` (exactly the
   displaced child S's mapped array and embedded map).
5. **Miss (fresh insert).** The insertion point is the first
   deleted (0x80) slot seen during the probe once a later
   group proves an empty byte exists; otherwise the first
   special byte of the group that contains an empty byte. If
   the byte at the remembered index is not special, the body
   rescans the control block from its start for the first
   special byte. It then stages the key descriptor and the
   new value on its stack and writes the whole bucket: key
   record at +0x00..0x18, value at +0x18..0x58. The pattern
   byte is written to the control byte at the slot index
   **and** to its mirror at `(index − 0x10) & mask`. The
   counters at map+0x10..0x20 are updated with one `psubq`
   against the constant `{0, −1}` at `0x450790`: item count
   (map+0x18) grows by 1 always; growth left (map+0x10)
   shrinks by `old_byte & 1` — 1 when the consumed slot was
   empty (0xff), 0 when it was deleted (0x80). Finally the
   body stores **only the qword 6** at out+0x00 and returns
   the out pointer — the variant the helper returns on with
   no cleanup, because nothing was displaced.
6. **Unwind.** The landing pad (`0x474ba2e`) drops the
   not-yet-inserted value argument through `0x474ac30`
   (boundary: a 45-byte S-value drop whose whole-.text direct
   census is this one call site at `0x474ba36`), frees the
   incoming key buffer through the dealloc slot the same way
   as the hit path, and resumes the unwind; the final tail
   call goes through slot `0x64df4c0` (→ `0x1680cab`).

## Limits

- The grow body `0x4742aa0` is hash-pinned only: how it
  picks the new capacity, reallocates the bucket/control
  block and rehashes the stored records is not traced here.
  Its `map+0x20` argument is recorded mechanically; what the
  callee reads from that address is part of that open edge.
- What `0x4742960` drops field by field inside the displaced
  sub-record, and the exact LSDA protection ranges behind
  the landing pad, are pinned by the frame records only.
- The probe's group-step arithmetic is recorded as the
  triangular hashbrown sequence from the loop increments;
  the small-table control-byte mirroring is recorded from
  the two store sites, without a separate capacity census.

## Next question

What does the grow body `0x4742aa0` (2,215 bytes, reached
only through slot `0x64eaf78`) do when growth left is 0 —
how does it choose the new capacity from the mask and item
count, how does it reallocate and rehash the bucket/control
block, what does it read at its `map+0x20` argument, and
which map words does it rewrite before the insert's probe
reloads them?

## Verification

- `tools/map_insert_static.py` re-derives every pin above
  from the authenticated binary: FDE extents and body hashes
  for the owner and all five boundaries, the whole-.text
  direct-call census for the owner and the value drop, all
  slot bindings via `.rela.dyn` and `.dynsym`, the
  empty-key FNV constant, and byte pins for the hash, the
  growth test, the probe loads, the candidate test, the hit
  copy, both control-byte stores, the counter store, the
  first bucket store and the tag-6 store.
- `tests/test_map_insert_static.py`: shape, slot bindings,
  census, layouts, five one-byte counterfactuals (FNV basis,
  growth-test field offset, tag-6 immediate, bcmp call,
  control-byte store), a generate round-trip, and equality
  with the committed `records.json`.

Made via @slopdotcash
Authored with AI assistance (Meta Muse Spark)
