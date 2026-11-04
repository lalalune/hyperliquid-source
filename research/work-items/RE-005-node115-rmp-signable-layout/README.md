# RE-005: node 115 `rmp_signable` serializer write order, variant rule and result tag byte

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for the write order, the variant rule, the
  tag-byte rule, the result-record constants and the unwrap site below, all
  re-derived from the pinned target bytes by the checker; **unresolved** for
  every naming or semantic claim listed under the boundary.

## The bounded question

One function in the pinned binary serializes a source record into a fresh
byte buffer and returns a small result record; its own failure path names
`l1/src/action/rmp_signable.rs` line 14, column 55. In what order, with what
widths and under what input rule does it write the payload, and what does
the returned record contain?

## Why this item

The operator action is reading the one RE-005 code-side binding that the
open rmp-signable packet (#2311) explicitly leaves unresolved: that packet
censuses the `.rodata` source record and states that no code-side binding
is claimed. The basis for the expected behaviour is the serializer's own
bytecode: a serializer's contract is the exact byte stream it emits, so
any reconstruction of the signing payload must reproduce this write order
and these two input rules exactly. The loss when it is wrong is a payload
whose bytes differ from the node's — a signature over different bytes.
Independence by repro case: the other two open RE-005 packets cover the
bincode varint size-state (#2257) and the bincode u64 reader state
(#2300), different functions in a different source file; neither touches
this serializer, its two callers, or the write-order question.

## Exact scope

| role | FDE half-open range | bytes | body SHA-256 |
| --- | --- | ---: | --- |
| serializer | `0x36aa9a0..0x36aade6` | 1,094 | `18c066ea3b97c2de167b8e7557d1e3e3cdbbd2f757dd83a00eafc827718eca9d` |
| caller_a | `0x36aadf0..0x36aaf0e` | 286 | `d334db07754d3444527141f0c43ec5316b25cef9dac35cfdb48a6728d6052127` |
| caller_b | `0x36aaf10..0x36aaff6` | 230 | `98513eb74d9449bf469425940d4ae673921f4494e34133e938a9f4f37f324582` |

Measured denominator: the serializer has exactly **2** direct call sites in
the whole `.text` (83,719,936 bytes), one inside each retained caller, and
no `.rela.dyn` entry references it. Both callers forward their own
arguments unchanged and post-process the result record.

## Trace

1. The serializer constructs a writer through `0x36b1600` with a spec
   record whose dword at offset 0x0c is `0x01000400`. If the constructed
   writer's first qword equals the sentinel `0x8000000000000004`, control
   reaches a panic whose message is `called \`Result::unwrap()\` on an
   \`Err\` value` (43 bytes) and whose location record is
   `l1/src/action/rmp_signable.rs`, line 14, column 55 — writer
   construction is unwrapped at that source site.
2. It then appends fields from the source record (third argument, `rcx`)
   through a grow helper (`0x43bd910`, requested sizes 8, 20, 8), checking
   remaining capacity before each write.
3. After the payload is complete it assembles a 0xe0-byte record (length
   mark `0x88` at offset 0xd0, word mark 1 at offset 0xd8) around the
   payload and a 0x20-byte record, and copies 32 resulting bytes into the
   result record.
4. It allocates one byte, stores the tag byte (below) into it, and fills
   the result record at the first argument (`rdi`).

## Result

Payload write order (offsets are into the source record):

| step | source | width | rule |
| ---: | --- | ---: | --- |
| 1 | `+0x10` | 8 | u64 stored big-endian (`bswap` before the store) |
| 2 | `+0x18` | 1 | byte `0x01` iff the stored byte equals 1, else `0x00` |
| 3 | `+0x19` | 20 | copied verbatim |
| 4 | — | 1 | single `0x00` byte, only when the dword at `+0x00` equals 1 |
| 5 | `+0x08` | 8 | u64 stored big-endian, only under the same variant rule |

The payload is therefore **29 bytes** when the variant dword differs from
1 and **38 bytes** when it equals 1.

Tag byte: the result string is a fresh 1-byte allocation holding `0x61`
when the tag argument (`edx`) equals 3, and `0x62` otherwise (computed as
`0x62 - (tag == 3)`).

Result record: qword `1` at `+0x00`, the tag-string pointer at `+0x08`,
qword `1` (length) at `+0x10`, the assembled 32 bytes at `+0x18`, the
constant `0x539` at `+0x38`, and zeros from `+0x40` through `+0x58`.

Boundary consumers: caller_a (`0x36aadf0`) writes result word `0x007e` on
one post-processing branch and `0x01a2` on the other; caller_b
(`0x36aaf10`) reaches the same `Result::unwrap()` panic message on its
discriminant-1 branch. Both are retained as boundary evidence only.

## Boundary

This packet does not name the action type the source record encodes, does
not claim the 32 assembled bytes are any particular hash, does not decode
the `0x01000400` writer spec dword, and does not follow the two callers'
own callers. The tag argument is forwarded by both callers, so which tag
values occur at runtime is not established here.

Next question: who calls caller_a and caller_b, and with which tag values
— that fixes which of the two tag bytes the node emits in practice.

## Reproduce

```sh
python3 -B tools/rmp_signable_layout_static.py --output research/work-items/RE-005-node115-rmp-signable-layout
python3 -B -m unittest discover -s tests -p 'test_rmp_signable_layout_static.py' -v
cd research/work-items/RE-005-node115-rmp-signable-layout && sha256sum -c MANIFEST.sha256
```

The checker authenticates the pinned binary (size and SHA-256) before any
analysis, re-derives every value above from the target bytes, validates
each pinned address as a native instruction start against GNU objdump
output, and carries corruption controls (mutated write, tag, variant and
location bytes, and a wrong public identity) that must all be rejected.
It writes only the packet directory, uses the Python standard library
plus the repository's own tools, and never executes the target.
