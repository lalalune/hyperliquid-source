# RE-015: the map grow's panic side — no pad in its frame, and none needed

Status: Result. This packet closes the one question the map-grow packet
(`RE-015-node115-map-grow`) left open in its final paragraph: what
happens to the records a panic could strand inside the rehash grow at
`0x4742aa0`. It introduces a reproducible standalone checker,
`tools/map_grow_panic_static.py`, and a test module,
`tests/test_map_grow_panic_static.py`.

The question decomposes exactly as the map-remove packet's closing
lines posed it: (a) does the grow's own frame carry a landing-pad
cleanup for the records its in-place fixup marks `0x80`, (b) does some
noreturn path in the panic machinery make the question moot, and (c)
how does whatever is found differ from the sibling grow at `0x4743990`,
whose landing pads call the pad helper at `0x4742680` and the
marked-record cleanup at `0x47425c0`.

The answer has three parts, each pinned below:

- The grow's frame has no landing pad at all. Its only FDE refers to
  the cluster-shared CIE at `0xca6ed8`, whose augmentation is exactly
  `zR` — no personality, no LSDA encoding — and the FDE carries no LSDA
  pointer.
- None is needed, and the reason is reachability rather than a
  noreturn abort. The body's only panic origin, the failure tail at
  `0x4743316`, is reachable solely from states in which nothing is
  marked: the three pre-split sizing branches to the failure stub at
  `0x4742bd1`, and the fresh path's null-allocation branch at
  `0x4742bfb`. After the path split the in-place path's only callee is
  `memmove` through its slot, so no panic can be raised inside the
  marking window, and the unwind that does leave the frame is handled
  one frame up by the caller's own pad, which drops only the caller's
  pending value and buffer.
- The sibling differs because it has a real exposure this grow lacks:
  its rehash calls the seeded SipHash callee at `0x4744490` once per
  record in both paths, i.e. from inside the marking window. Its LSDA
  therefore wires a fresh-path pad to the pad helper, an in-place pad
  to the marked-record cleanup, and a panic-in-cleanup guard pad around
  the cleanup call itself.

## Question source

The map-grow packet closed by recording that the register-only caller
convention around the `insert` at `0x474b620` leaves one part of the
contract unrecovered: "What the landing pads do when a panic unwinds
through the grow between the in-place fixup marking a slot and the
scan relocating it remains open." The map-remove packet's
next-question line posed the comparison directly: read the LSDA chain
of this grow at `0x4742aa0`, identify what drops the `0x80`-marked
records when a panic lands mid-rehash, and compare with the sibling
grow at `0x4743990` whose pads call `0x4742680` and `0x47425c0`.

## Boundary inventory

Body boundaries are exact FDE extents. Owners are the bodies the
question is about; boundary bodies close the ranges around them.

| Role | FDE extent | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| grow (owner) | `0x4742aa0..0x4743347` | 2215 | `dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67` |
| sibling grow (owner) | `0x4743990..0x4743ff0` | 1648 | `eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef` |
| marked cleanup (owner) | `0x47425c0..0x4742676` | 182 | `a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73d983d86b584a3e49e4` |
| pad helper (owner) | `0x4742680..0x47426d1` | 81 | `da0038dfd88d2675f82db29375445a91dc3116e140ab87ae02e1c6eac7fb3401` |
| previous body | `0x4742850..0x4742958` | 264 | `19805cd457f128d16f1325f9b077f925f5dde1d5246cb6374881910ed5b03288` |
| whole-map drop | `0x4742960..0x4742a93` | 307 | `1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1` |
| next body | `0x4743350..0x474398c` | 1084 | `bc09ee782d62721d2cbc93cc2e52d6f447caebbf7ef36da19f5ae89cfef84ae4` |
| insert (caller) | `0x474b620..0x474ba5d` | 1085 | `f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658` |
| sibling hasher | `0x4744490..0x47445fb` | 363 | `a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c363bc7fe23f9c757f62` |
| insert value drop | `0x474ac30..0x474ac5d` | 45 | `a40c63266a40637f39a94b76a535c5f934ad1679a466075465f8f8871e569c87` |

The panic-path shims are pinned the same way: the Rust personality at
`0x5cad7b0..0x5cadd4f` (1439 bytes,
`fc2600274388c9ee5a7c1aec72fae9aebbb6dffb18ee91059e8b3679ec92d677`),
the panic formatter at `0x1680e80..0x1680eac` (44 bytes,
`28fc3434a04bb9e49d5a0164306a5c31abf6bce26425d99d27031ac1c9beb2e3`),
the panic implementation shim at `0x5c826c0..0x5c826dd` (29 bytes,
`ae57c1f06e3254ce7cd3518d42154be71831103b748b6f19f74cacc64c5fb766`),
the allocation-error adapter at `0x141e251..0x141e264` (19 bytes,
`8443a2a6c5074055f5abdf1b4b2041c6434ff00ba23ebfcb33a91176170035b9`),
the allocation handler shim at `0x5c827a0..0x5c827b3` (19 bytes,
`0c812a743791010c3c3ec26bb02400d2081851a700c58237af89161da151228e`),
the panic-in-cleanup guard at `0x1680cab..0x1680cbf` (20 bytes,
`7604c0d4f26a7d70e59c5dcb8a39928bfd7207a5d4439d91d8fb1e50be9846e7`) and
its panic entry at `0x1680e40..0x1680e5e` (30 bytes,
`8506c2e60ef3206c2566cee1c87d5709e1a0b4651094519c2d07355a9deec427`).

## (a) The grow's own frame carries no LSDA

The cluster's bodies split across exactly two CIEs. One, at
`0x103d604`, has augmentation `zPLR`: it declares the personality slot
`0x64efa28` and LSDA pointer encoding `0x1b`. The other, at `0xca6ed8`,
has augmentation exactly `zR`: it declares neither a personality (`P`)
nor an LSDA encoding (`L`), so an FDE referring to it cannot name a
language-specific data area at all.

The grow's FDE uses the `zR` CIE, and its LSDA field is absent. It is
the only FDE covering `0x4742aa0..0x4743347`, and no other FDE overlaps
the range (the checker enumerates all FDEs against the range). The
same `zR` CIE covers the marked cleanup, the pad helper, the whole-map
drop and the previous and next bodies; the frames that do run cleanup
actions — the sibling grow, the insert, the insert helper at
`0x4741960`, the payload constructor at `0x4741180` and the wrapper
constructor at `0x4742470` — all use the `zPLR` CIE. So during an
unwind the grow's frame contributes register restoration only: there
is no pad in this frame that could drop anything, marked or otherwise.

## (b) The marked state and a panic never coexist in this frame

The failure tail at `0x4743316` — `lea` of the message at `0x49bd80`
("Hash table capacity overflow"), message length `0x39`, the
panic-formatter call at `0x4743329` through slot `0x64df6b8`, then the
allocation-error call at `0x4743337` through slot `0x64df490` — is the
body's only panic origin. A raw scan of the body's bytes for every
rel8/rel32 branch whose target is the failure stub at `0x4742bd1` or
the tail finds exactly four sites, and each is additionally pinned by
its full instruction bytes:

| Site | Branch | State at the branch |
| --- | --- | --- |
| `0x4742ab7` | `jb` to the stub | entry checked-add overflow |
| `0x4742b5b` | `ja` to the stub | capacity-cap check |
| `0x4742b9f` | `jo` to the stub | entry size-overflow check |
| `0x4742bd3` | stub's own `jne` to the tail | dispatch on the fallibility byte |

All four sit before the path split at `0x4742c24`. The only other
route into the tail is the fresh path's null-allocation wiring: the
`je` at `0x4742bfb` on the allocator's null return lands at
`0x474329b`, which tests the same fallibility byte and either returns
the empty-table tag (`0x10`) or jumps to `0x474332f`, the tail's
allocation-error half. The fresh path never marks: it writes pattern
bytes into a not-yet-installed table (map-grow packet, fresh-grow
phase). So every state that can raise this frame's panic has an
untouched old table and no marks anywhere.

After the split, the in-place path — the only path that writes `0x80`
marks — makes exactly one call: `memmove` through slot `0x64df568` at
`0x4742f33`, to mirror the fixed-up control bytes before scanning. The
fresh rehash loop and the in-place scan contain no call at all. The
body's complete call inventory is the six slot calls (allocator at
`0x4742bf2`, `memset` at `0x4742c34`, `memmove` at `0x4742f33`,
deallocator at `0x4743301`, and the two tail calls), pinned
instruction-by-instruction by the map-grow packet and re-pinned here
because the verdict rests on them. There is no per-record or user-code
callee inside the marking window, so no panic can be raised there; and
even a panic raised inside one of the slot callees would find no pad
to run in this frame, per part (a).

Nor is the panic a process-level noreturn that bypasses unwinding.
The formatter at `0x1680e80` assembles its message/location pair on
the stack and calls slot `0x64e1f30`, bound by relocation to the panic
implementation shim at `0x5c826c0`, after which the body is `int3`
fill — the shim does not return into the formatter. The cleanup
frames' personality is live: slot `0x64efa28` of the `zPLR` CIE is a
type-8 RELATIVE relocation whose addend is `0x5cad7b0`, and that body
has the canonical Rust personality shape — it compares its first
argument against the search-phase value `1` and reads the LSDA,
instruction pointer and region start through the GLOB_DAT accessor
slots `0x64eca58`, `0x64eca60` and `0x64eca68` (bound by `.dynsym`
name to `_Unwind_GetLanguageSpecificData`, `_Unwind_GetIPInfo` and
`_Unwind_GetRegionStart`). Panics in this binary do unwind; the
sibling's and the insert's pads in part (c) are the proof.

When the unwind crosses the grow's frame it reaches the caller. The
insert's LSDA (at `0x34caf4`) assigns the range
`0x474b9ee..0x474ba11`, which covers the grow call at `0x474ba06`, the
pad at `0x474ba2e`. That pad drops the insert's own pending value
through the body at `0x474ac30`, frees the insert's pending buffer
through the deallocator slot when a flag word is set, and resumes the
unwind. It never calls the marked cleanup, the pad helper or the
whole-map drop — consistent with there being nothing map-side to
clean up at that point.

## (c) Why the sibling grow is wired differently

The sibling grow at `0x4743990` is the same raw-table grow shape for a
different map (map-grow packet), but its rehash is not inlined: it
calls the callee at `0x4744490` once per record in both paths — at
`0x4743be4` on the fresh path and at `0x4743d5d` inside the in-place
relocation loop. The callee is a seeded hash body: its prologue mixes
the two 16-byte constant blocks at `0x4522f0` and `0x4511c0`, whose
words are the four SipHash initial constants (the string
"somepseudorandomlygeneratedbytes" read as little-endian words). A
binary-wide direct-call census finds exactly six call sites for it;
the two sibling sites are the only ones inside a grow.

A per-record call inside the marking window is a real exposure: the
callee can raise (or be unwound through) while records sit marked. The
sibling's frame is therefore built under the `zPLR` CIE, and its LSDA
(at `0x34c4f8`; header `ff 9b`, call-site table 40 bytes, type-table
base `0x34c528`) wires seven ranges. Only three carry pads:

| Protected range | Covers | Pad | Pad action |
| --- | --- | --- | --- |
| `0x4743bdf..0x4743be9` | the fresh-path hasher call | `0x4743fc0` | call the pad helper at `0x4742680` with the stack descriptor at `[rsp+0x20]`, then `_Unwind_Resume` |
| `0x4743d58..0x4743d62` | the in-place hasher call | `0x4743fd5` | call the marked cleanup at `0x47425c0` with the descriptor at `[rsp+0x20]`, then `_Unwind_Resume` |
| `0x4743fd8..0x4743fe2` | the cleanup pad's own call | `0x4743fea` | call the panic-in-cleanup guard through slot `0x64df4c0`; the LSDA's only action-bearing entry (action field 1) |

The two helpers do the two different jobs the two paths need (both
established by the map-remove packet and re-pinned here as owners and
sole-caller censuses): the pad helper at `0x4742680` computes the
not-yet-installed fresh allocation's extent from its descriptor and
tail-jumps to the deallocator slot; the cleanup at `0x47425c0` blanks
each `0x80` mark to `0xff` in the control bytes and their mirror,
calls the descriptor's drop function on the record, decrements the
item count and recomputes the growth-left field. Each has exactly one
caller in the binary — its pad. The guard pad handles the second-order
case: if the cleanup itself panics, slot `0x64df4c0` is bound to the
body at `0x1680cab`, which calls its panic entry at `0x1680e40` with
the 36-byte string at `0x46e9bd`, "panic in a destructor during
cleanup", instead of unwinding further. The insert carries the same
guard pattern around its own pad (range `0x474ba31..0x474ba3b`, pad
`0x474ba57`, also action-bearing).

This grow inlines FNV-1a in both of its loops (map-grow packet: the
empty-key constant `0xaf64724c8602eb6e` and the prime
`0x100000001b3` are loaded as immediates and multiplied in place) and
calls nothing per record, so LLVM emitted it under the plain `zR` CIE
with no LSDA at all. The presence or absence of pads in this cluster
tracks exactly the presence or absence of a call inside the marking
window.

## Boundary decisions and limits

- The LSDA action fields are reported mechanically. Three pads in the
  two tables carry action field `1`; the record at the head of each
  action table reads `7f 00`. What the value selects beyond naming
  that record is not interpreted: the pads' observable difference is
  in their bodies (a guarded cleanup call versus an unguarded drop
  sequence), and the packet claims only that.
- The failure tail's own continuation is recorded, not interpreted:
  after the allocation-error call at `0x4743337` the tail loads `0x10`
  into `edi` and jumps to `0x4742f16`, inside the in-place scan setup.
  Both tail callees are non-returning in the configured build (the
  panic formatter's body ends in `int3` fill after its implementation
  call, and the allocation-error adapter at `0x141e251` forwards to
  the handler shim at `0x5c827a0`), and no marked state exists at the
  tail regardless, so the continuation has no bearing on the verdict.
- Whether the sibling's hasher at `0x4744490` can itself panic is not
  established and is not needed: the sibling's pads exist because a
  call sits in the window (an unwind can also arrive from deeper
  frames), while this grow has no call in the window at all.
- Naming stays at the level the predecessors set: the bodies are the
  S cluster's grow, its sibling grow, its marked-record cleanup and
  its single insert entry. No Rust item path is asserted for the panic
  shims beyond their relocation- and string-level identities.
- Which value type either map holds, and therefore what any record
  drop would run, remains open exactly as the earlier packets left it;
  it does not affect this question, since the drop owner here is a
  frame-table fact, not a value-semantics fact.

## Answers to the three sub-questions

(a) No. The grow's frame records provide no landing pad and no
cleanup: the FDE's CIE declares no LSDA encoding and the FDE carries
no LSDA pointer.

(b) No noreturn path is needed to make the question moot, and the
panic machinery here does unwind. The question is moot on
reachability grounds: every branch that can reach the body's panic
origin fires before any record is marked, and the marking window
contains no call that could raise.

(c) The sibling's pads exist because its rehash calls a seeded SipHash
callee once per record inside the marking window. Its fresh-path pad
frees the pending allocation through `0x4742680`, its in-place pad
drops marked records through `0x47425c0`, and its cleanup call is
itself guarded against a second panic. This grow has the same marking
fixup but no in-window callee, so its frame carries neither a
personality nor an LSDA.

## Evidence

- `records.json` — extents, SHA-256 values and raw FDE/CIE bytes for
  the four owner bodies, the six boundary bodies and the seven
  panic-path shims; the per-body unwind records (CIE, augmentation,
  LSDA); the decoded sibling and insert LSDA tables with their blob
  hashes; the personality and slot bindings; the failure-branch
  census; the grow's slot-call inventory; the direct-call censuses;
  the SipHash constant blocks; and the guard and panic strings.
- `frames.txt` — native readelf frame-interpolation rows for all
  seventeen pinned bodies.
- `grow_failure_entry_objdump.txt` — the grow's entry, the three
  sizing branches, the failure stub, the allocator call, the
  null-allocation branch and the `memset` call.
- `grow_install_tail_objdump.txt` — the null-allocation block, the
  install stores, the deallocator call and the failure tail.
- `sibling_hash_call_fresh_objdump.txt` and
  `sibling_hash_call_inplace_objdump.txt` — the two protected ranges
  and their hasher calls.
- `sibling_pads_objdump.txt` — the sibling's own failure tail and all
  three landing pads.
- `insert_pads_objdump.txt` — the insert's value-drop pad and its
  guard pad.
- `pad_helper_objdump.txt` — the pad helper's extent computation and
  deallocator tail jump.
- `panic_guard_objdump.txt` — the guard body's string load and panic
  entry call.
- `panic_fmt_objdump.txt` — the formatter's payload assembly and
  implementation call.

Reproduce with a materialized node #115 artifact:

```sh
python3 -m unittest tests.test_map_grow_panic_static -v
```

or directly:

```sh
python3 tools/map_grow_panic_static.py
```

The standalone tool prints the same records this packet commits; the
tests additionally mutate single bytes — a sibling LSDA pad offset,
the cleanup pad's call displacement, a stub branch displacement, the
personality relocation's addend, and a guard-string byte — and
require the analysis to reject every mutation.

---
*Packet prepared on branch `packet/re015-grow-panic-cleanup`, based on
upstream commit
`05bc2de303c05525b71e7e257426e741bc66a390`.*
