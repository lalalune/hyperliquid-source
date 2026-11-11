# RE-015: the sibling grow's seeded hasher cannot panic — and its callers' pads cover it anyway

Status: Result. This packet closes the one sentence the grow-panic
packet (`RE-015-node115-map-grow-panic`, PR #2934) left explicitly
unestablished in its limits: "Whether the sibling's hasher at
`0x4744490` can itself panic is not established and is not needed:
the sibling's pads exist because a call sits in the window." It
introduces a reproducible standalone checker,
`tools/sibling_hasher_panic_static.py`, and a test module,
`tests/test_sibling_hasher_panic_static.py`.

The answer has three parts, each pinned below:

- The hasher cannot itself panic. Its body is straight-line apart
  from its calls — a byte-exact linear decode of its 363 bytes
  finds no branch, no division and no overflow-checked operation —
  and its only FDE refers to the cluster-shared CIE at `0xca6ed8`,
  whose augmentation is exactly `zR`: no personality, no LSDA.
- Neither can anything it calls. The body makes exactly two calls,
  both direct, both to the buffered absorb at `0x4744980`; the
  absorb is a leaf (no call of any form; its fifteen branches all
  land inside its own extent) under the same plain-`zR` frame
  shape. The transitive call graph beneath the hasher closes after
  one step and contains no panic origin.
- The coverage that does exist sits one frame up and is complete
  across the binary: all six direct call sites of the hasher lie
  inside padded ranges of their callers' LSDAs, each pad dropping
  that caller's own state — the sibling's two ranges on the pad
  helper and the marked-record cleanup (grow-panic packet), caller
  A's two ranges on its own cleanup pads, caller B's range on a
  decrement pad, caller C's range on a buffer-freeing pad.

## Question source

The map-grow packet (PR #2758) established that the sibling grow at
`0x4743990` calls the seeded SipHash callee at `0x4744490` once per
record in both rehash paths. The map-remove packet (PR #2766) posed
the panic question the grow-panic packet then answered for the grow
at `0x4742aa0`; that packet (PR #2934) showed the sibling's LSDA
wires pads around the two hasher calls, and closed by recording
that the hasher's own panic-ability was "not established and is not
needed". This packet establishes it, because the completeness of
the cluster's panic story otherwise rests on an unexamined callee:
if the callee could raise, the sibling's pads would be load-bearing
in a way no packet had verified; since it cannot, the pads are
coverage for an exposure the callee side never realises.

## Boundary inventory

Body boundaries are exact FDE extents. Owners are the bodies the
question is about; boundary bodies close the ranges around them.

| Role | FDE extent | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| seeded hasher (owner) | `0x4744490..0x47445fb` | 363 | `a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c363bc7fe23f9c757f62` |
| absorb (owner) | `0x4744980..0x4744b57` | 471 | `2de0e4e06f65af3f729cc6b2a4d12d7dcbbcb25902272a15c5f238c5096ed8b0` |
| sibling grow | `0x4743990..0x4743ff0` | 1632 | `eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef` |
| caller A | `0x4748500..0x4749aa9` | 5545 | `7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91ec06977ea9b2691` |
| caller B | `0x474a160..0x474a36c` | 524 | `a2ca8b7c65a4ed7eb69ff5fb090acb7daead9c234e681b0867b3d0c70a1b5d7d` |
| caller C | `0x474ba60..0x474bcd3` | 627 | `4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44` |
| previous hash body | `0x4744330..0x4744490` | 352 | `6a63f80b87467acfa021f1e6f6348428254af8bf6eb366a0b6c23c762053df69` |
| next hash body | `0x4744600..0x474476a` | 362 | `45b8c11384591251d95dfd535ffa593b439d7f0f2673e141dcd44888e88bcdc1` |

The one shim this packet relies on is pinned the same way: the Rust
personality at `0x5cad7b0..0x5cadd4f` (1439 bytes,
`fc2600274388c9ee5a7c1aec72fae9aebbb6dffb18ee91059e8b3679ec92d677`),
bound by the type-8 RELATIVE relocation in slot `0x64efa28` of the
callers' `zPLR` CIE — the same binding the grow-panic packet
established, re-derived here from `.rela.dyn`.

## (a) The hasher's own frame carries no LSDA

The hasher's only FDE (at `0xefd12c`) refers to the CIE at
`0xca6ed8`, whose augmentation is exactly `zR`: it declares neither
a personality (`P`) nor an LSDA encoding (`L`), and the FDE carries
no LSDA pointer. It is the only FDE covering
`0x4744490..0x47445fb`, and no other FDE overlaps the range (the
checker enumerates all FDEs against the range). The absorb's frame
(at `0xefd1ac`) is the same shape, as are the frames of the two
neighbouring hash bodies that share the absorb. So during an unwind
none of these frames contributes anything but register restoration:
there is no pad in the hasher's frame that could run, whatever
arrived there.

## (b) Nothing beneath the hasher can raise

A linear decode of the hasher body — native objdump, required by
`decode_export` to be byte-exact and contiguous over the extent,
and cross-checked against a raw census of `0xe8` bytes (the body's
only two are the call instructions themselves) — finds 93
instructions:

- two calls, at `0x47444eb` and `0x4744502`, both direct, both to
  the absorb at `0x4744980`;
- no branch of any kind (the SipHash rounds are fully unrolled);
- no division, no trap instruction, and no overflow branch —
  every arithmetic operation in the body is a wrapping add, xor,
  rotate or fixed-count shift on registers or stack slots.

The two calls are the seeded-hash streaming pattern: the prologue
builds the four-word state on the stack from the 16-byte seed at
`[rdi]`, XORed with the two constant blocks at `0x4522f0` and
`0x4511c0` (the SipHash initial constants, re-pinned here from the
grow-panic packet); the first call absorbs the record bytes
described by the incoming pair at `[rsi+0x8]` and `[rsi+0x10]`, and
the second absorbs the single `0xff` byte the prologue plants at
`[rsp+0xf]`, with length 1 — after which the finalisation rounds
run inline and the body returns.

The absorb at `0x4744980` is the buffered `write` half of the same
hasher: it adds the incoming length to the total counter at
`[rdi+0x30]`, tops up the eight-byte tail buffer at `[rdi+0x38]`
(tail length at `[rdi+0x40]`), and runs the compression rounds over
each full block. Its 141 instructions contain no call of any form
(and no `0xe8` byte anywhere), no division and no trap; its
fifteen branches — the tail-packing and block loops — all land
inside its own extent. Its one add of an untrusted length, the
total counter, is unchecked: neither body contains an overflow
branch (`jo`/`jno`) anywhere, so the counter wraps silently rather
than raising, in line with the release-build arithmetic the rest of
the cluster shows.

The transitive call graph beneath the hasher is therefore closed:
hasher → absorb → (nothing). No frame in it names a panic origin —
no call to the panic formatter, no checked operation with a failure
target, no division — so there is no state in which an unwind can
originate at or below any hasher call site. The direct-call census
of the absorb over the whole `.text` finds six sites: the hasher's
two, plus two each in the neighbouring hash bodies at `0x4744330`
and `0x4744600`, which are separate seeded-hash bodies of the same
cluster (both plain-`zR`, both pinned here as boundaries); whatever
they establish is their own packets' business, but their presence
confirms the absorb is a shared leaf, not a hasher-private helper
with a second, caller-supplied exit.

## (c) Every caller covers its hasher call anyway

A binary-wide direct-call census finds exactly six call sites for
the hasher. Each sits inside a padded range of its caller's LSDA
(the tables are decoded byte-by-byte and pinned by SHA-256 in
`records.json`; the sibling's table is re-pinned from the
grow-panic packet):

| Call site | Caller | Covering range | Landing pad | Pad's job |
| --- | --- | --- | --- | --- |
| `0x4743be4` | sibling grow `0x4743990` | `0x4743bdf..0x4743be9` | `0x4743fc0` | pad helper `0x4742680` frees the pending fresh allocation (grow-panic packet) |
| `0x4743d5d` | sibling grow `0x4743990` | `0x4743d58..0x4743d62` | `0x4743fd5` | marked-record cleanup `0x47425c0` drops the marked records (grow-panic packet) |
| `0x4748984` | caller A `0x4748500` | `0x4748977..0x4748989` | `0x4749948` | saves the exception object, frees a pending buffer through the deallocation slot `0x64df4a0`, drops two stack values, rejoins the body's common resume tail |
| `0x47491b3` | caller A `0x4748500` | `0x47491a3..0x47491b8` | `0x4749814` | the same shape: deallocation-slot free, two stack-value drops, common resume tail |
| `0x474a1c3` | caller B `0x474a160` | `0x474a1c0..0x474a1c8` | `0x474a361` | decrements the qword at `[rbx]`, then `_Unwind_Resume` |
| `0x474ba7e` | caller C `0x474ba60` | `0x474ba7b..0x474ba83` | `0x474bcb4` | frees the pending buffer `([r14], [r14+0x8])` through the deallocation slot when non-null, then `_Unwind_Resume` |

So the sibling's wiring is not an anomaly: it is the cluster-wide
pattern. Any unwind whose return address landed at a hasher call —
which part (b) shows cannot originate below the call — would be
caught by the first frame that has state of its own to drop, and
that frame is always the caller, never the hasher. The sibling's
in-place pad remains the only one whose job is the marked records,
because the sibling is the only caller that calls the hasher from
inside a marking window.

## Boundary decisions and limits

- The LSDA action fields are reported mechanically. The sibling's
  and caller A's tables end their action tables with the head bytes
  `7f 00` and carry action-bearing guard entries over their own
  pads (caller A: the ranges at `0x474983e`, `0x474987d` and
  `0x47498df`, the last of which also covers the two hasher-call
  pads — the pads' own helper calls are guarded the same way the
  sibling's cleanup call is). Caller B's and C's tables use the
  omitted-ttype header shape and their action-table heads read
  `00 00`; no entry in either carries an action. What an action
  value selects beyond naming its record is not interpreted, as in
  the predecessor packets.
- The call censuses are direct-call censuses, the cluster's
  standing convention: an indirect call through a register or a
  table could in principle name the hasher without leaving an
  `0xe8` site, and no packet in this cluster claims to census
  those. The hasher's own outgoing calls are additionally pinned
  instruction-by-instruction through the byte-exact decode, so the
  transitive half of the verdict does not rest on the census
  convention.
- Both owner bodies read through caller-supplied pointers (the
  seed block, the record bytes, the state struct). A wild pointer
  there faults at the operating-system level; a fault is not an
  unwind, no frame record governs it, and it is outside the
  question the predecessors posed, which is about the panic path.
- Naming stays at the level the predecessors set: the callee is
  the seeded SipHash body the map-grow packet identified by its
  constant blocks, the absorb is its buffered-write half, and the
  three further callers are named only by their extents (caller A,
  B, C). No Rust item path is asserted for any of them, and which
  value type any caller's map holds remains open exactly as the
  earlier packets left it.

## Answers to the question

Can the sibling's hasher at `0x4744490` itself panic? No — and
neither can its only callee. Its frame records therefore cover
nothing: the `zR` CIE gives it neither a personality nor an LSDA.
The sibling's pad wiring covers the two hasher *call instructions*
in the sibling's frame, and the same completeness holds at the
other four call sites in the binary — every caller catches its own
hasher call with its own cleanup pad, so the wiring would be
load-bearing exactly if the callee could raise, which it
mechanically cannot.

## Evidence

- `records.json` — extents, SHA-256 values and raw FDE/CIE bytes
  for the two owner bodies, the six boundary bodies and the
  personality shim; the per-body unwind records; the instruction
  censuses of both owner bodies; the whole-`.text` direct-call
  censuses of the hasher and the absorb; the four decoded LSDA
  tables with their blob hashes; the per-site coverage map; the
  personality and deallocation slot bindings; and the SipHash
  constant blocks.
- `frames.txt` — native readelf frame-interpolation rows for all
  nine pinned bodies.
- `hasher_objdump.txt` — the full hasher body: seed setup, the two
  absorb calls, the unrolled rounds.
- `absorb_objdump.txt` — the full absorb body: tail packing, the
  block loop, the remainder packing; no call anywhere.
- `sibling_hasher_call_fresh_objdump.txt` and
  `sibling_hasher_call_inplace_objdump.txt` — the sibling's two
  protected ranges and their hasher calls.
- `caller_a_call_first_objdump.txt`,
  `caller_a_call_second_objdump.txt`,
  `caller_a_pad_first_objdump.txt` and
  `caller_a_pad_second_objdump.txt` — caller A's two hasher calls
  and the two pads their ranges land on.
- `caller_b_call_objdump.txt` and `caller_b_pad_objdump.txt` —
  caller B's hasher call and its decrement pad.
- `caller_c_call_objdump.txt` and `caller_c_pad_objdump.txt` —
  caller C's hasher call and its buffer-freeing pad.

Reproduce with a materialized node #115 artifact:

```sh
python3 -m unittest tests.test_sibling_hasher_panic_static -v
```

or directly:

```sh
python3 tools/sibling_hasher_panic_static.py
```

The standalone tool prints the same records this packet commits;
the tests additionally mutate single bytes — a hasher absorb-call
displacement, a caller-B LSDA pad offset, the personality
relocation's addend, and an absorb body byte — and require the
analysis to reject every mutation.

---
*Packet prepared on branch `packet/re015-sibling-hasher-panic`,
based on upstream commit
`05bc2de303c05525b71e7e257426e741bc66a390`.*
