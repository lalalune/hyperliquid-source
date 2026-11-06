# RE-015 — node 115 map removal side: no single-entry erase body exists for the S-rooted map — the only removal-flavoured body in its cluster is the sibling grow's unwind cleanup of fixup-marked records, and entries otherwise leave only through the whole-table recursive drop; and the grow body 0x4742aa0 has exactly one referrer in every form, the insert's (map, 1, map+0x20, 1) call

Questions (carried by the map-grow packet
RE-015-node115-map-grow):

> (1) Which body removes an entry from the S-rooted
> hashbrown map (map words at S+0x20: +0x00 ctrl base,
> +0x08 mask, +0x10 growth-left, +0x18 items) — does it
> clear the control byte to a 0x80 tombstone, or does it
> do backward-shift deletion (moving subsequent records)?
> What happens to items/growth-left and the removed value
> (returned, dropped, freed)?
>
> (2) Does anything ever reach the grow body 0x4742aa0
> with a fallibility byte of 0, or with an additional
> argument other than 1, through a different referrer in
> any reference form (direct E8, rela addends, absolute
> words, lea)?

Answer, in one line: **no body removes a single entry
from this map. The censused candidate sets for an erase
are empty or untied (below), the map's traced operation
set is build / grow / lookup / replace-on-hit /
whole-table drop, and the one removal-flavoured body in
the cluster — the marked-record cleanup 0x47425c0 — is
not a consumer erase at all: it runs only from a landing
pad of the sibling (seeded-hash) grow 0x4743990, and it
blanks the 0x80 fixup marks that grow's in-place rehash
leaves behind to 0xff (slot plus mirror), drops each
marked record through a descriptor function pointer,
decrements the item count once per record, and
recomputes growth-left = cap − items at the end. No body
clears a live entry of this map to a tombstone as an
erase, and no body performs backward-shift deletion for
it; entries leave only when the whole table is dropped
by 0x4742960, or when an insert hit hands the displaced
value to the caller. And (2): the grow body has exactly
one referrer in every censused form — the insert's call
through slot 0x64eaf78 at 0x474ba06 with (map, 1,
map+0x20, 1) — so no fallibility-0 or additional ≠ 1
call exists in this binary.**

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| marked-record cleanup | `0x47425c0..0x4742676` | 182 | `a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73d983d86b584a3e49e4` |
| map drop (whole-table) | `0x4742960..0x4742a93` | 307 | `1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1` |

The map-drop hash is the same one the insert-helper,
map-insert and map-grow packets pin for this body as a
boundary (there named displaced-record drop); this packet
is the first to trace it as an owner.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| map lookup | `0x4742130..0x4742470` | `930b9aa4933c3aab6513d5f1df4ffb9578225cbe084873a6063f65cc10201a2f` |
| wrap ctor (payload ctor's caller) | `0x4742470..0x4742595` | `fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c` |
| next landing-pad helper | `0x4742680..0x47426d1` | `da0038dfd88d2675f82db29375445a91dc3116e140ab87ae02e1c6eac7fb3401` |
| map grow | `0x4742aa0..0x4743347` | `dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67` |
| sibling grow | `0x4743990..0x4743ff0` | `eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef` |
| map insert | `0x474b620..0x474ba5d` | `f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658` |
| insert helper | `0x4741960..0x4742124` | `19ab10dcba77aea7e558737bddc7bace985b7d49bc254b69d731e23bb805136d` |

Slot bindings (`.rela.dyn`): dealloc `0x64df4a0` →
`0x635de30`; grow function `0x64eaf78` → `0x4742aa0`;
sibling grow function `0x64eaf88` → `0x4743990`.

## Question (1) — the candidate censuses (the negative, bounded)

The search started from the map's consumer side — the
insert helper's tree operations and the payload ctor's
readers — and censused candidate bodies by the marks an
erase for this map would have to leave: it must hash or
otherwise find this map's keys (bucket size 0x58, the
0xff-terminated FNV-1a, `bcmp` confirmation), write a
control byte (tombstone 0x80, or 0xff where the probe
chains allow), and move the counters at map+0x10/+0x18.
Results, all whole-.text unless noted:

- **FNV-1a basis loads**: 20 bodies in the whole binary
  contain the basis immediate. Inside the S family
  cluster (0x4740000..0x4750000) they are exactly the
  insert helper `0x4741960`, the lookup `0x4742130`, the
  grow `0x4742aa0` and the insert `0x474b620`. The lookup
  was read in full for this packet: it splits the key on
  "::", probes, and returns a pointer into the hit
  bucket's child S — it contains no store outside its
  own stack frame. There is no fifth body that hashes
  this map's keys.
- **Immediate 0x80 byte stores with a map tie**: 55
  bodies in the binary store an immediate 0x80 byte
  somewhere; the subset that also carries any tie to a
  0x58-bucket map (imul by 0x58, the FNV basis, a `bcmp`
  slot call, or a call to this map's drop `0x4742960`)
  is **empty**.
- **erase_no_drop shape** (REX tzcnt + REX bsr/lzcnt +
  a register byte store — the neighbouring-group
  empty-run computation): exactly two bodies in the
  binary, `0x143f000` and `0x63bb7e0`; neither has imul
  0x58, the FNV basis, a `bcmp` call or a record-drop
  call, and both sit outside the cluster. They belong
  to other maps and are named here as the whole
  candidate set of that shape.
- **0x80 materialised into a byte register + imul
  0x58**: 45 bodies binary-wide; the cluster subset is
  **empty**.
- **Immediate byte stores inside the cluster**: no body
  in 0x4740000..0x4750000 stores an immediate 0x80 byte
  at all. The immediate 0xff stores in the range are
  the grow family's in-place "source becomes empty"
  stores (grow: 0x474320c / 0x4743211; sibling grows:
  0x474386b / 0x4743871 and 0x4743eb1 / 0x4743eb8), the
  set bodies' hash stores (0x4744385, 0x47444f0,
  0x474465f), and the cleanup owner's two stores below.
- **Item-count decrements**: the only sub/dec-form
  decrement of a qword at [reg+0x18] in the cluster
  range is the cleanup owner's own `dec` at 0x474263b.

## The marked-record cleanup 0x47425c0 — what it actually is

The body's sole caller in the whole binary is the call
at `0x4743fdd`, inside a landing pad of the sibling
grow `0x4743990` (the seeded-hash map family; its
reserve slot is `0x64eaf88`, its in-place fixup loads
the same 0x80 vector at `0x454f80`, e.g. at
`0x4743cb8`). The pad passes `rdi = [rsp+0x20]`, a stack
descriptor:

| Descriptor offset | Use in this body |
| ---: | --- |
| +0x00 | the map pointer (`rbx`): ctrl at +0x00, mask at +0x08, growth-left at +0x10, items at +0x18 |
| +0x08 | a record drop function pointer (`r14`); null on entry skips the scan entirely |
| +0x10 | the record stride (`r12`): the dropped record pointer advances by −stride per scanned index |

Behaviour, phase by phase:

1. **Scan.** Control bytes are visited from index 0
   upward. Each byte is compared against 0
   (`cmp cl, [rax+rbp+0x10]` at `0x4742616`, with
   `rbp = index − 0x10`); the loop advances while the
   byte subtraction does not overflow (`jno` at
   `0x474261a`) — only the byte 0x80 stops the scan.
   0x80 is exactly the mark the sibling grow's in-place
   fixup writes over live records before re-placing
   them, so the scan finds records that were marked
   but never re-placed — the state a panic mid-rehash
   leaves behind. The scan ends at the mask-derived
   bound computed in the advance step.
2. **Per marked slot.** The mask is reloaded
   (`0x474261c`), and 0xff is stored at the slot
   (`0x4742623`) and at its mirror
   (`ctrl + (rbp & mask) + 0x10`, `0x474262b`) — the
   same two positions the insert writes a pattern byte
   to. The record (at `ctrl` plus the accumulated
   −index·stride offset) is dropped through the
   descriptor's function pointer (`call r14` at
   `0x4742636`), and the item count at map+0x18 is
   decremented by one (`dec` at `0x474263b`). No record
   is moved; no other slot is touched.
3. **Finish.** Growth-left is recomputed as
   cap(mask + 1) − items with the grow packet's
   capacity model (the `cmovb` small-table form
   included) and stored at map+0x10 (`0x4742663`). The
   control pointer and the mask are never stored. A
   mask of −1 on entry skips straight to this finish.

So this body does remove entries — but only the
fixup-marked leftovers of an aborted in-place rehash,
only for the sibling map, and only on the unwind path.
It is not reachable from any consumer of either map,
it is not this map's erase (this map's grow has no
direct calls at all and never calls it, in any form),
and its per-entry effect is the opposite assignment
from a tombstone erase: marked (0x80) → empty (0xff),
with the record dropped and items decremented.

## The map drop 0x4742960 — the removal side that exists

Called with a map pointer (`rdi` = &child S+0x20 in the
insert helper's displaced-value path):

1. **Gate.** The mask at map+0x08 is loaded first
   (`0x474296e`); zero returns at once — an empty map's
   control pointer is the static empty block, not heap.
   The item count at map+0x18 (`0x4742985`) bounds the
   walk.
2. **Walk.** Control groups are loaded in order
   (`movdqa` at `0x474299a`, `pmovmskb` at `0x47429a4`);
   the inverted group mask selects the full
   (non-special) lanes. Each group step moves the
   bucket cursor by −0x580 (16 buckets of 0x58); a lane
   resolves with `tzcnt` (`0x47429fc`) and an imul by
   0x58 (`0x4742a03`).
3. **Per live bucket.** The key buffer at bucket+0x08
   is freed through the dealloc slot (`0x4742a1b`) when
   the key record's first word at bucket+0x00 is
   nonzero (size = that word). The child S mapped array
   (buffer at bucket+0x28, count at bucket+0x20) is
   freed through the same slot (`0x4742a34`) when the
   count is nonzero (size = count·8). The body then
   recurses into the child S's embedded map at
   bucket+0x38 (self-call at `0x47429c1`) — each nested
   map is torn down the same way, depth-first as the
   walk proceeds.
4. **Finish.** The body tail-jumps to the dealloc slot
   (`0x4742a7e`) with the allocation base
   (ctrl − align16(buckets·0x58)) and the total size
   (align16(buckets·0x58) + buckets + 16, the imul at
   `0x4742a44`). No control byte is rewritten, and
   neither map+0x10 nor map+0x18 is ever stored: the
   table ceases to exist rather than shrinking.

Its whole-.text caller census (E8/E9) is six sites, all
drop or displaced-value contexts: `0x47408db` (a shared
drop body), `0x474205d` (the insert helper dropping a
displaced record), the self-recursion `0x47429c1`,
`0x474b419` (a second shared drop body), and the two
45-byte value-drop tails `0x4740a58` / `0x474ac58`
(E9). No lookup, insert or consumer body calls it to
remove an entry.

Together with the earlier packets this closes the S
map's operation set: entries are created by the insert,
displaced (copied out, then dropped by the caller) on
an insert hit, read by the lookup, and destroyed in
bulk by this drop. Single-entry removal is simply not
instantiated for this map in node #115 — consistent
with its consumers, which build the tree once and only
read it afterwards.

## Question (2) — the grow reachability census

Scope: the whole binary, all sections, every reference
form either packet series has used. Results:

| Form | To body 0x4742aa0 | To slot 0x64eaf78 |
| --- | --- | --- |
| direct E8 call / E9 jump | none | n/a |
| ff15/ff25 call/jmp through slot | n/a | `0x474ba06` only |
| other rip-relative forms (lea, mov load/store, cmp/test, ff group; REX.W and non-REX) | none | `0x474ba06` only |
| `.rela.dyn` addend carriers | the slot entry itself (type 8) | n/a |
| `.rela.plt` addend carriers | none | n/a |
| absolute 64-bit word in the file | only that entry's addend field | only that entry's offset field |

The rip-relative row is a byte-pattern census over the
enumerated opcode forms, corroborated independently by
a full `objdump -d` disassembly of the binary greped
for the two addresses: the only annotated reference is
the same call at `0x474ba06`. The absolute-word row is
a whole-file scan: the body value occurs once (file
offset of the `.rela.dyn` entry's addend) and the slot
value once (the same entry's offset field, 16 bytes
earlier) — there is no pointer to the grow body in
`.data.rel.ro`, `.rodata`, or anywhere else.

The one call is the map insert's, set up at
`0x474b9ee..0x474ba01` (pinned by the insert packet):
`rdi` = map, `rsi` = 1 (additional), `rdx` = map+0x20,
`ecx` = 1 (fallibility byte). Therefore nothing in
this binary reaches the grow body with a fallibility
byte of 0 or an additional other than 1: the failure
returns the grow packet recorded for byte 0 (rax = 0
on overflow, rax = 0x10 on null allocation) are dead
code paths from every referrer that exists. (The
body's FDE in `.eh_frame` / `.eh_frame_hdr` names its
extent for unwinding — metadata pinned as frame
records by all RE-015 packets — and is not a call
path; a related binary section outside this capture
is out of scope by construction.)

## Limits

- The negative in question (1) is bounded by the
  censused candidate sets above: an erase that neither
  hashes this map's keys in its own body, nor stores a
  0x80/0xff control byte in any censused form, nor
  decrements the item count, nor ties to the 0x58
  bucket layout would be invisible to these censuses —
  and would also be unable to perform the removal.
  A bucket-pointer erase helper fed by a separate find
  body is the one shape not fully excluded by shape
  alone; it is excluded by the caller side instead:
  the only find body for this map (the lookup) has
  exactly two callers (`0x4740368`, `0x4740745`, both
  read-side S consumers) and returns into read paths,
  and no cluster body outside the two owners stores
  to a control byte with a computed value while
  touching this map's counters.
- The cleanup owner's descriptor is read from its own
  loads and its sole caller's landing pad; what the
  sibling grow stores into the descriptor's +0x10
  field on the non-unwind path, and the second pad
  helper `0x4742680`, are pinned as boundaries only.
- The cleanup scan's end bound is recorded from the
  advance arithmetic at `0x4742600..0x4742611` without
  a separate formal proof.
- Landing-pad / LSDA protection ranges are pinned by
  the frame records only.

## Next question

The S map's own grow `0x4742aa0` contains no direct
call and no marked-record cleanup: when a panic lands
mid-rehash inside it, what (if anything) drops the
records its in-place fixup marked 0x80 — is there a
landing-pad cleanup in its own frame records, does the
process take a noreturn path that makes the question
moot, and how does that differ from the sibling grow
`0x4743990`, whose pads call `0x4742680` and the
cleanup owner `0x47425c0`?

## Verification

- `tools/map_remove_static.py` re-derives every pin
  above from the authenticated binary: FDE extents and
  body hashes for both owners and all seven boundaries,
  the FNV body census, the tied / tzcnt-bsr / mov-0x80
  candidate censuses, the cluster immediate-store
  census, the caller censuses for the cleanup, the
  drop and the lookup, the full grow reference census
  (direct, slot, rip-relative, rela addends, absolute
  words), all slot bindings via `.rela.dyn`, and byte
  pins for the cleanup's scan, both 0xff stores, the
  drop call and the item decrement, and for the drop's
  group walk, per-bucket frees, recursion and final
  dealloc.
- `tests/test_map_remove_static.py`: shape, slot
  bindings, both censuses, caller census, layouts,
  five one-byte counterfactuals (cleanup item
  decrement, cleanup 0xff store, drop tzcnt, grow slot
  call, cleanup caller), a generate round-trip, and
  equality with the committed `records.json`.

Made via @slopdotcash
Authored with AI assistance (Meta Muse Spark)
