# RE-006 node 115 remaining cursor-search members

## Scope

Packet `RE-006-node115-remaining-members` completes the RE-006 cursor
family census. The family census in
`RE-006-node115-variant-cursor-searches` (#2530) lists thirteen
standalone search bodies; the packets #2416, #2427, #2493, #2503,
#2530, #2542, #2546 and #2548 pin twelve of the family's records but
leave six members unpinned. This packet pins those six — the bodies at
`0x35bd8a0`, `0x35bddb0`, `0x35be3b0`, `0x35bf3c0`, `0x1d65b20` and
`0x4d380a0` — against the Linux x86-64 node 115 artifact (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes; file offset = VA − 0x1000 in the standalone copy).
None of the six is pinned by any earlier packet; the near-name bodies
`0x1d65920` and `0x35bdd20` (#2503) and `0x35bd660` / `0x35bd800`
(#2530) are different functions (`0x35bddb0` starts one byte after
`0x35bdd20`'s FDE ends, and `0x35bd8a0` starts 0xe bytes after
`0x35bd800`'s FDE ends).

Every member writes the same 32-byte result record (flag at +0x0,
node at +0x8, height at +0x10, position at +0x18) and shares the
family epilogue shape: flag 0 on a hit, flag 1 on a miss. Everything
else — node layout, compare form, call-site count, consumption — is
verified per body below, because family members have repeatedly
differed in more than one displacement.

## Short answer

- All six bodies are exact 146-byte FDEs with pinned SHA-256 digests.
  Five digests are distinct: `0x1d65b20` and `0x4d380a0` are
  **byte-identical clones** of one another at two addresses.
- The byte scan finds **11 direct call sites** (0 tail calls, 0
  `R_X86_64_RELATIVE` references). That corrects the census counts
  carried since #2530: `0x1d65b20` and `0x4d380a0` have **two** call
  sites each, not one — each is called from a pair of clone callers.
- Node layouts: u64 keys for five bodies (27, 11, 38, 110 and 110 keys
  per node) and u32 keys for one (11 per node). The u32 body at
  `0x35be3b0` is the family's only **signed** member (`setl`/`setg`/
  `sub` three-way compare) and the only one that scans its node
  linearly, one key per step.
- Consumption splits 2 / 9: the two `0x35bd8a0` sites are flag-only
  (the flag is loaded with `movzbl` into a register and tested later —
  a third flag-consumption form next to the family's dword `cmpl` and
  byte `cmpb` forms); the other nine sites consume node + position
  with element strides 0x30 (×1), 0x10 (×2), 0x14 (×2) and 0x48 (×4).
- Fallbacks are per-layout, not per-family: five distinct fallback
  bodies across the nine node+position sites (`0x4551810`,
  `0x4551c20`, `0x45585e0`, `0x24c9200`, `0x57f7210`), and the
  `0x35bd8a0` caller has no fallback at all.
- Height verdict: **the returned height is never consumed as a
  number** — not at any of the 11 sites, and not anywhere else in the
  eight census units. The height slot is read 10 times across all
  caller FDEs: 1 vector struct copy and 9 reads belonging to other
  phases of the two callers that reuse the frame record; 6 of the 8
  units never read it at all.

## Method

1. Pin each body and caller by exact FDE extent and SHA-256 digest
   and pin every instruction row of the six bodies (39–40 rows each).
   Verify each node's layout from the body's own instructions: the
   count load pins the count offset, the key compare pins the scan
   displacement (key base = displacement − key width, the scan index
   starts at −1), and the descent load pins the child-edge base.
   Keys-per-node then follows by the trailer arithmetic stated per
   body, and is asserted to close exactly.
2. Census the bodies' direct callers by byte scan: every `E8` (direct
   call), `E9` (tail call) and `R_X86_64_RELATIVE` addend in the
   artifact that targets a body start. The census must reproduce the
   retained site set exactly.
3. Per call site, pin a window covering the argument setup, the call
   and the flag test, and prove consumption field by field: for a
   node+position site, verify the position load, the scale chain (one
   or two instructions whose composed multiplier is the element
   stride), and the node add, then prove with a block walk from the
   flag test that the add sits on the hit side (for a dword
   `cmpl $0x1` test, equality is the miss). For a flag-only site,
   verify no record field besides the flag is read after the call
   inside the window. Separately, run a whole-FDE slot census per
   (caller, record base) unit: every read of the flag / node / height
   / position stack slots in the entire caller FDE must match the
   retained census.
4. Attribute every height-slot read the census finds: a vector
   mnemonic classes it as a struct copy; anything else must be pinned
   by an attribution window showing the read belongs to another phase
   of the caller. A height read lying inside a site's own call window
   or hit window would be a consumption, and the tool asserts none
   exists.

## Member `0x35bd8a0` — gapless 27-key u64 search, flag-only sites

- Premises: FDE `0x35bd8a0..0x35bd932` (146 bytes), SHA-256
  `499fcf8ff6b95a70aa3be671ee130d699c83c694ff57a9af4f2e05d45ce7a848`.
  2 direct call sites, 0 tail calls, 0 rela references.
- Layout: u64 keys at node +0x8, count word at +0xe6, child edges at
  +0xe8 (count+2, an 8-byte trailer with no gap word). The trailer
  leaves (0xe6−6−0x8)/8 = 27 keys per node; the child-index word sits
  inside that trailer at the family position count−2 (+0xe4), named
  by arithmetic only — no member reads it.
- Trace: key dereference `0x35bd8a3`, count load `0x35bd8a6`, key
  compare `0x35bd8c5`, descent load `0x35bd90c`, hit flag-zero
  `0x35bd919`, miss flag-one `0x35bd92b`. Unsigned compare.
- Callers and consumption: both sites (`0x450c4aa`, `0x450c5eb`) live
  in one 812-byte caller, `0x450c430..0x450c75c`, itself a
  membership-probe loop over a sorted key array: it copies an
  argument triple into frame slots at entry (root at 0x8(%rsp),
  height at 0x10(%rsp)) and probes repeatedly, staging the key at
  (%rsp) and the record at rsp+0x28. Root and height are reloaded
  from the frame slots per probe (`handle_stack` presentation). The
  flag is consumed in **register form**: `movzbl 0x28(%rsp),%eax` at
  `0x450c4b4` / `0x450c5f5`, tested by a later `test %al,%al`. No
  other record field is read after either call — the whole-FDE
  census for this unit is flag 2, node 0, height 0, position 0, so
  the flag-only verdict holds over the entire caller, not just the
  windows.
- Fallback: none. The caller's only other callee is `0x4555f40`
  (twice), a child-step helper called with a child pointer on both
  the hit and miss paths; there is no tag check and no family
  fallback in this caller.
- Height verdict: never read in this caller.

## Member `0x35bddb0` — gapped 11-key u64 search behind a 0x218 head

- Premises: FDE `0x35bddb0..0x35bde42` (146 bytes), SHA-256
  `30f297e738540fa348b161115181d87d0a28167d35a6bc1086a8f701e8793058`.
  1 direct call site, 0 tail calls, 0 rela references.
- Layout: u64 keys at node +0x218 (the keys sit behind a 0x218-byte
  head), count at +0x272, edges at +0x278 (count+6: the gapped
  trailer — child-index u16 at +0x270, count u16 at +0x272, 4-byte
  gap). Keys per node (0x272−2−0x218)/8 = 11.
- Trace: count load `0x35bddb6`, key compare `0x35bddd5`, descent
  load `0x35bde1c`, hit flag-zero `0x35bde29`, miss flag-one
  `0x35bde3b`. Unsigned compare.
- Caller and consumption: site `0x44829ab` in caller
  `0x4482950..0x44830f3` (1,955 bytes). The handle is in %rbx (root
  at +0x8, height at +0x10); the record is at rsp+0x20 and the key
  pointer is a frame slot at rsp+0xa0 staged from the object's +0x58
  field. Flag test `cmpl $0x1,0x20(%rsp)` at `0x44829b0` (dword). On
  the hit (fall-through) side the caller consumes node + position
  with a **two-instruction scale chain**: `mov 0x38(%rsp),%rax`
  (position), `lea (%rax,%rax,2),%r8` (×3), `shl $0x4,%r8` (×16),
  `add 0x28(%rsp),%r8` (node) — element stride **0x30**.
- Fallback: `0x4551810`, called at `0x44829da` on the handle's
  non-sentinel path with (handle, key pointer) — not the u64 family's
  `0x4556410`.
- Height verdict: the record's height slot (rsp+0x30) is read twice
  in the caller, at `0x4482cda` and `0x4483022`, both in later phases
  that reuse the frame record (the first alongside fresh reads of
  the node and position slots, in a phase that does its own cursor
  arithmetic and writes the position slot back; the second passes
  the height as a call argument together with a node-derived
  value). Neither lies in the site's window; both are pinned by
  attribution windows.
  Census: flag 3, node 3, height 2, position 2.

## Member `0x35be3b0` — signed u32 search, linear in-node scan

- Premises: FDE `0x35be3b0..0x35be442` (146 bytes), SHA-256
  `0a725341981473211a1f193625896b37ba3fbaaa69354f56b7b222651d9db4b8`.
  2 direct call sites, 0 tail calls, 0 rela references.
- Layout: u32 keys at node +0xb8, count at +0xe6, edges at +0xe8
  (count+2, the u32 sub-family trailer; child-index u16 at +0xe4).
  Keys per node (0xe6−2−0xb8)/4 = 11.
- Trace: key dereference `0x35be3b3`, count load `0x35be3b5`, key
  compare `0x35be3d5`, descent load `0x35be41c`, hit flag-zero
  `0x35be429`, miss flag-one `0x35be43b`.
- Compare form: **signed** — the only signed member in the family.
  The compare at `0x35be3d5` produces a three-way result through
  `setl %r11b` / `setg %r10b` / `sub %r11b,%r10b` (`0x35be3dc`,
  `0x35be3e0`, `0x35be3e4`); every other member uses the unsigned
  `seta`/`sbb` form. The scan loop at `0x35be3d0` also differs: it
  advances the index by one key per step (`inc %rdi`, count
  decremented by the 4-byte key size) — a linear scan of the node —
  where the u64 members reload the index from a computed step.
- Caller and consumption: sites `0x2c81276` and `0x2c815b1` in caller
  `0x2c81080..0x2c81bc0` (2,880 bytes). The handle is in %r15, at
  +0x20 for the first site and +0x28 for the second (tag compared
  against the sentinel, root and height at handle +0x8/+0x10). The
  record is at rsp+0x30; the key pointer is the frame slot at
  rsp+0x10. Flag test `cmpl $0x1,0x30(%rsp)` (dword) at each site+5.
  On the hit side: `mov 0x48(%rsp),%rax` (position), `shl $0x4,%rax`
  (×16), `add 0x38(%rsp),%rax` (node) — element stride **0x10**.
- Fallback: `0x4551c20`, called at `0x2c812a9` / `0x2c815d9` on the
  non-sentinel path with (&handle, key pointer) — again not
  `0x4556410`.
- Height verdict: never read in this caller. Census: flag 2, node 2,
  height 0, position 2 — the only record reads are the two sites'
  own flag tests and consumption chains.

## Member `0x35bf3c0` — gapless 38-key u64 search in the giant caller

- Premises: FDE `0x35bf3c0..0x35bf452` (146 bytes), SHA-256
  `89516192c291c89a0ae1ee5c9a2a0783b50e2b61be0187805455e6ba2a30c229`.
  2 direct call sites, 0 tail calls, 0 rela references.
- Layout: u64 keys at node +0x8, count at +0x13e, edges at +0x140
  (count+2, gapless 8-byte trailer). Keys per node
  (0x13e−6−0x8)/8 = 38; child-index position inferred at +0x13c.
- Trace: count load `0x35bf3c6`, key compare `0x35bf3e5`, descent
  load `0x35bf42c`, hit flag-zero `0x35bf439`, miss flag-one
  `0x35bf44b`. Unsigned compare.
- Caller and consumption: sites `0x4474e57` and `0x4475469` in caller
  `0x4473d10..0x44770e5` (13,269 bytes) — the same giant caller the
  runner-up packet (#2546) pins for three of its sites; this packet
  pins the identical FDE digest for it. The record is at rsp+0x110;
  root and height come from frame slots 0x38(%rsp) / 0x40(%rsp)
  (`handle_stack`). Site 1 passes the record in %rbx (defining
  `lea 0x110(%rsp),%rbx` at `0x4474d98`); site 2 uses a direct
  `lea 0x110(%rsp),%rdi`. Flag test `cmpl $0x1,0x110(%rsp)` (dword),
  but here the hit side is the **jump target** (`jne` — everything
  but flag 1 is a hit): the consumption sits in separate hit blocks
  at `0x4474ed0` and `0x447554c`, byte-parallel to each other:
  `mov 0x118(%rsp),%rax` (node), `mov 0x128(%rsp),%rcx` (position),
  `lea (%rcx,%rcx,4),%rcx` (×5), `lea (%rax,%rcx,4),%rax`
  (node + position×20) — element stride **0x14** — followed by
  `add $0x60,%rax`: the consumer continues into the field at
  element +0x60.
- Fallback: `0x45585e0`, called at `0x4474e7b` / `0x4475505` on the
  non-sentinel path with a handle pointer loaded from a frame slot
  and the key at rsp+0x340.
- Height verdict: the height slot (rsp+0x120) is read 8 times in
  this caller — the most of any unit — and none of the reads is a
  consumption of this search's result. One (`0x4474bf3`) is a
  `movups` whole-record copy. The other seven belong to other
  phases that reuse rsp+0x110 as a scratch record: two read the
  height alongside the position as helper-call arguments
  (`0x4474af8`, `0x4475f09`), one compares it (`0x4474b16`), one
  adds it into a bound (`0x4476258`), one passes it onward with the
  node (`0x44761ea`), one compares it against a register
  (`0x4475f2d`), and one (`0x44754b3`) reads it as an index into a
  table **after the different callee `0x3905a40` has been called
  with this record** at `0x447549d` — i.e. it consumes that callee's
  output in the reused slot, not this search's. Every read is
  pinned by an attribution window. Census: flag 12, node 9,
  height 8, position 7.

## Members `0x1d65b20` and `0x4d380a0` — the byte-identical wide-node pair

- Premises: FDEs `0x1d65b20..0x1d65bb2` and `0x4d380a0..0x4d38132`
  (146 bytes each), both SHA-256
  `b1d2c6ba43757c25e56ffeef32b4ee8127289eb49a3361b808cb361b5fd8866d`
  — the same bytes at two addresses, the family's only clone pair.
  2 direct call sites each (clone caller pairs), 0 tail calls, 0
  rela references.
- Layout: u64 keys at node +0x8, count at +0x37a, edges at +0x380
  (count+6, gapped trailer; child-index at +0x378). Keys per node
  (0x37a−2−0x8)/8 = **110** — a wide flat node, far beyond the
  11–38 keys of every other member. (Arithmetic from the pinned
  offsets; the node contents are not reconstructed.)
- Trace (offsets identical in both): count load at body +0x6, key
  compare at +0x25, descent load at +0x6c, hit flag-zero at +0x79,
  miss flag-one at +0x8b. Unsigned compare.
- Callers and consumption: `0x1d65b20` is called at `0x2bafd30`
  (caller `0x2bafce0..0x2baff7a`) and `0x2baffd0` (caller
  `0x2baff80..0x2bb021a`), two adjacent 666-byte clone FDEs;
  `0x4d380a0` at `0x57c9480` (caller `0x57c9430..0x57c96bb`) and
  `0x57c9710` (caller `0x57c96c0..0x57c994b`), two adjacent
  651-byte clone FDEs. All four callers share one shape: the handle
  is a function argument (%r14 resp. %r15) whose fields sit one
  word later than usual — tag at +0x18, root at +0x20, height at
  +0x28, bound at +0x30; the key is the caller's own argument
  staged at rsp+0x8 (resp. rsp+0x18); the record is at rsp+0x68
  (resp. rsp+0x78). Flag test `cmpl $0x1` on the record (dword).
  On the hit side all four consume identically: node load,
  position load, `lea (%rcx,%rcx,8),%rcx` (×9), then
  `lea (%rax,%rcx,8),%r` (node + position×72) — element stride
  **0x48** — followed by `add $0x60`, continuing into the field at
  element +0x60, the same bias the giant caller's sites use.
- Fallbacks: per-address-space pairs again — `0x24c9200` for the
  `0x1d65b20` callers (called with &handle+0x18 and the key slot),
  `0x57f7210` for the `0x4d380a0` callers.
- Height verdict: never read in any of the four callers. Census per
  unit: flag 1, node 1, height 0, position 1 — the single node and
  position reads are the consumption chain itself.

## Height verdict (all six members)

Across the eight (caller, record-base) census units, the height
slot is read 10 times: 1 vector struct copy and 9 other-phase reads,
all in the two callers that reuse their frame record across phases
(`0x4482950`, `0x4473d10`). No read lies inside any site's call
window or hit window, no caller passes the returned height to the
scale chain, a comparison, or a call as this search's result, and 6
of the 8 units never read the slot at all. **No member's height is
consumed as a number anywhere the census can see.** This matches
the verdict of every earlier RE-006 packet.

## Negative results

- No tail-call (`E9`) site and no `R_X86_64_RELATIVE` reference
  targets any of the six bodies; the 11 `E8` sites are all the
  direct callers there are.
- The two walker-caller sites have no fallback: the caller contains
  no call to any of the family's five fallbacks used here, nor to
  the `0x4556410` / `0x4556c50` fallbacks of the earlier packets.
- No site consumes the record through a byte `cmpb` flag test in
  this packet (9 dword, 2 register, 0 byte).
- No height read is a consumption (see above).

## Boundaries

- Static evidence only: nothing here executes the node, and no
  runtime behaviour is claimed.
- Fallback bodies are identified by their call sites only; their
  bytes are not pinned by this packet.
- The child-index word is never read by any member body; its offset
  is named by the layout arithmetic only, and for the two gapless
  members its position inside the 8-byte trailer is inferred
  (count−2), not instruction-verified.
- Element contents beyond the strides (0x30, 0x10, 0x14, 0x48) and
  the +0x60 field bias at the stride-0x14 and stride-0x48 sites are
  not reconstructed; the stride is the pinned fact.
- The 110-key layout of the wide pair is the arithmetic consequence
  of the pinned offsets; whether such nodes occur in practice is
  outside static reach.

## Next question

With this packet the #2530 family census is fully pinned. The
largest open consumption question in the family is unchanged: the
callee reached through GOT slot `0x64e7198`, which the sibling
packet's 60 join sites call with node + position×0xb0 — its identity
gates what those joins do with the element. Behind it queue the
element layouts for the six strides now known (0xb0, 0x40, 0x30,
0x10, 0x14, 0x48) and the five unpinned fallback bodies recorded
here (`0x4551810`, `0x4551c20`, `0x45585e0`, `0x24c9200`,
`0x57f7210`).

## Reproduction

```
python3 -m unittest tests.test_remaining_members_static
python3 tools/verify_packets.py research/work-items/RE-006-node115-remaining-members
sha256sum -c research/work-items/RE-006-node115-remaining-members/MANIFEST.sha256
```

The tests materialise the node 115 artifact at
`artifacts/node/115/hl-node` (git LFS) and regenerate `records.json`,
`frames.txt` and the six body exports byte for byte; `analyze()`
checks every claim in this README against the artifact bytes without
authenticating first, so a flipped byte fails the specific check
that covers it.
