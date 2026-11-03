# RE-006 node 115: who fills the drivers' element argument

## Scope

PR #2564 pinned the four insert-or-assign drivers of the
sibling-search node layout (`caller_a` `0x2dc3900`, `caller_b1`
`0x3ce15b0`, `caller_b2` `0x3f1a150`, `caller_c` `0x4dd2ca0`) and
showed that each receives the 0xb0-byte element as a caller-supplied
argument and only forwards it or copies it wholesale into the nodes.
Its boundary census left the drivers' 13 direct E8 call sites in 11
FDEs untraced. This packet traces exactly those 13 sites and answers,
for each one, how the element buffer handed to the driver is
produced: per-field stores in the calling FDE (a), a wholesale copy
from another buffer (b), or an incoming argument of the calling FDE
itself (c).

Static analysis only, against node 115
(sha256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
No artifact code was executed.

## Short answer

Exactly **one** of the 13 sites is filled per-field. FDE `0x36a1330`,
on `caller_b2`'s only site, builds the element on its own stack at
`[rsp+0x1c8]` immediately before the call, storing all eight fields
the join callee reads:

| field | value | writer |
| --- | --- | --- |
| +0x40 | 0 | `movq $0x0` store at `0x36a1a29` |
| +0x58 | 10^14 (`0x5af3107a4000`) | store at `0x36a1a4f` (movabs at `0x36a1a45`) |
| +0x60 | 0 | `movq $0x0` store at `0x36a1a57` |
| +0x78 | 10^14 | store at `0x36a1a73` (same movabs) |
| +0x80 | source element +0x8 | movups store at `0x36a1a0c` |
| +0x88 | source element +0x10 | same movups |
| +0x90 | source element +0x18 | movups store at `0x36a1a04` |
| +0x98 | source element +0x20 | same movups |

The source of the four copied fields is the FDE's own 4th-argument
element (base register `rbx` = `rcx` at entry; loads at
`0x36a19fd`/`0x36a1a00`). The constructed element is a near-identity
image: both product terms of the join callee vanish (the +0x40 and
+0x60 factors are 0) at the callee's own scale (10^14), while the
clamp pair (+0x90/+0x98) is inherited from the source element.

The other 12 sites split evenly:

- **(c) incoming argument, 6 sites.** The three join-consumer clones
  pinned by PR #2558 (`0x2a89500`, `0x55a07e0`, `0x55a12e0`) pass a
  cursor into a 0xb0-stride array received as their own 5th argument
  (`rbp = r8` in the prologue, advanced by 0xb0 after the driver
  call). Three small adapters forward an argument unchanged:
  `0x369a3d0` its 3rd (`rcx = rdx`), `0x369b650` its 4th (`rcx` is
  never written before the call; the element is the head of the
  argument struct, whose tail fields at +0xb0/+0xb8/+0xc0 the FDE
  reads), `0x3f10ac0` its 1st (`rcx = r15 = rdi`). No store through
  the element register exists in any of the six FDEs (extractor
  census: 0).
- **(b) wholesale copy, 6 sites.** `0x2c62590` stages the result
  record of its lookup helper into the element (below).
  `0x2c64870` and `0x55e3770` (two sites each) run
  `memcpy(element_buffer, r12, 0xf8)` immediately before each
  driver-call phase, where `r12` is the lookup-phase record pointer
  (the found record, or the FDE's staging record at
  `[rsp+0x140]`/`[rsp+0x150]` on the miss arm); earlier decode fills
  of the same stack buffers (calls at `0x2c64ad1`/`0x2c64bda` in
  `0x2c64870`, `0x55e3cda` in `0x55e3770`) are superseded by that
  memcpy on the driver path, and the buffers' only direct stores
  touch the head qwords (+0x0/+0x10), never a field displacement.
  `0x55defd0` rebuilds its element buffer as a tag-qword store
  (`0x55e13fa`), a byte store at +8 (`0x55e1406`), and
  `memcpy(element+9, [rsp+0x410], 0xa7)` (`0x55e1425`) — full 0xb0
  coverage, all eight fields from the `[rsp+0x410]` record.

## The `0x2c62590` staging, precisely

This FDE's 12 per-field stack stores do **not** build the element:
they build the *query* record at `[rsp+0x20]` for the lookup helper
`0x2762570`, which reads exactly those offsets through `rdx`
(+0x0, +0x10, +0x20, +0x28, +0x30, +0x38, +0x4c…, +0x60, +0x61) and
stores nothing through `rdx` (census: 0). The helper writes a
0x118-byte result record through its `rdi` (its own final
`memcpy` of 0x118 bytes at `0x2762756`, plus tag/byte stores on the
error arms). Back in `0x2c62590`, the element at `[rsp+0x218]` is
staged from that result record at `[rsp+0x100]`: the tag qword is
stored directly (`0x2c62697`), and bytes [8, 0xb0) arrive through two
memcpys — result+8 → query buffer (0xe0 bytes, `0x2c62678`), then
query buffer → element+8 (0xa8 bytes, `0x2c626b4`) — so element byte
*m* equals result-record byte *m* for every *m* in [0, 0xb0).

## Signature refinement

`caller_a`, `caller_b1` and `caller_c` take the element as the 4th
argument (`rcx`; each saves `rcx` first in its prologue).
`caller_b2` takes it as the **3rd** argument (`rdx`): its only call
site passes the element in `rdx`, and `caller_b2`'s pinned body
memcpys 0xb0 bytes from `rdx` on its miss arm. This refines PR
#2564's collective "4th argument" phrasing.

## Boundary

The per-field writer is now located for the `caller_b2` chain (FDE
`0x36a1330` itself). For the remaining 12 sites it sits one more
level up, at exactly these producers:

- whoever fills the 5th-argument element arrays of `0x2a89500`,
  `0x55a07e0`, `0x55a12e0`, the 3rd-argument array of `0x369a3d0`,
  the 4th-argument struct of `0x369b650`, and the 1st-argument
  record of `0x3f10ac0`;
- whoever produces the lookup-phase records that `r12` points to in
  `0x2c64870` and `0x55e3770`;
- the production of helper `0x2762570`'s result record (its
  serialised tail is assembled from a sub-lookup at `0x2bb7270` and
  0x10f-byte serialisation copies inside the helper);
- whoever assembles the `[rsp+0x410]` record in `0x55defd0` from
  its serialised-record scratch.

## Files

- `records.json` — authenticated findings (extractor output):
  per-site classifications, per-FDE store/memcpy censuses, the cb2
  field attribution, and the re-derived boundary census.
- `frames.txt` — the readelf FDE lines for the 16 pinned bodies
  (11 boundary FDEs, the lookup helper, the 4 drivers).
- `*_full_body_*_objdump.txt` — full intel-syntax disassembly
  exports of the 9 smaller bodies (each ≤ 2,816 bytes); the three
  large boundary FDEs (`0x2c64870`, `0x55e3770`, `0x55defd0`) are
  pinned by digest plus selected instruction rows in the extractor.
- `MANIFEST.sha256` — hashes of the packet files.
- Extractor: `tools/element_argument_static.py`; tests:
  `tests/test_element_argument_static.py`.
