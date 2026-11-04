# RE-005: node 115 `rmp_signable` serializer write order, variant rule and result tag byte

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Original packet base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
  Correction base: `05bc2de303c05525b71e7e257426e741bc66a390`;
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

## Original packet context

The original packet investigated the RE-005 code-side binding that
the rmp-signable packet (#2311) explicitly leaves unresolved: that packet
censuses the `.rodata` source record and states that no code-side binding
is claimed. The basis for the expected behaviour is the serializer's own
bytecode: a serializer's contract is the exact byte stream it emits, so
any reconstruction of the signing payload must reproduce this write order
and these two input rules exactly. The loss when it is wrong is a payload
whose bytes differ from the node's — a signature over different bytes.
Independence by repro case: the other two contemporary RE-005 packets cover the
bincode varint size-state (#2257) and the bincode u64 reader state
(#2300), different functions in a different source file; neither touches
this serializer, its two callers, or the write-order question.

## Correction on the current base

The retained producer and records incorrectly described the 20-byte field
as unconditional, called the continuation head an error sentinel, and
reported 29/38 as complete payload lengths. Reading the complete native
body establishes the conditional 9/18/29/38-byte suffixes and leaves the
helper-produced prefix unresolved. This corrects the existing packet from
PR #2399; it adds no second ownership or coverage claim for these bodies.

The old producer's ten tests passed while a static reproduction found two
wrong length classes and accepted all four deciding branch-polarity flips.
The same final fifteen test methods fail against the base producer and
pass against the corrected producer. See [validation evidence](VALIDATION.md)
for the actual logs, source identities, commands and limits. Existing full
native exports remain byte-identical; all component gates remain false.

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

1. The initial writer helper `0x36b1600` receives a spec pointer at
   `rsp+0x20`; the dword at `rsp+0x28` (relative offset `+0x08`) is
   `0x01000400`. The returned first qword is compared with
   `0x8000000000000004` at `0x36aaa05`. The **JNE** at `0x36aaa0d`
   sends unequal values to `0x36aad04`; equality continues at `0x36aaa13`.
   On the unequal route, after conditional buffer release, a diagnostic
   call uses the message `called \`Result::unwrap()\` on an
   \`Err\` value` (43 bytes) and whose location record is
   `l1/src/action/rmp_signable.rs`, line 14, column 55 — writer
   construction is unwrapped at that source site. The body has UD2 after
   that call; the diagnostic, release and unwind helpers remain unclosed.
2. On the continuation route, the buffer length is loaded from the
   helper-updated `rsp+0x50`. The pre-call zero initialization does not prove
   this length remains zero: the helper received a pointer to the writer
   triple. Its initial bytes and length are unresolved. The body appends
   fields from the source record (fourth argument, `rcx`)
   through a grow helper (`0x43bd910`, requested sizes 8, 20, 8), checking
   remaining capacity before each write.
3. After the payload is complete it assembles a 0xe0-byte record (length
   mark `0x88` at offset 0xd0, word mark 1 at offset 0xd8) around the
   payload and a 0x20-byte record, and copies 32 resulting bytes into the
   result record.
4. It allocates one byte, stores the tag byte (below) into it, and fills
   the result record at the first argument (`rdi`).

## Result

Appended suffix order (offsets are into the source record):

| step | source | width | rule |
| ---: | --- | ---: | --- |
| 1 | `+0x10` | 8 | u64 stored big-endian (`bswap` before the store) |
| 2 | `+0x18` | 1 | byte `0x01` iff the stored byte equals 1, else `0x00` |
| 3 | `+0x19` | 20 | copied verbatim only when the byte at `+0x18` equals 1 |
| 4 | — | 1 | single `0x00` byte, only when the dword at `+0x00` equals 1 |
| 5 | `+0x08` | 8 | u64 stored big-endian, only under the same variant rule |

The JNE at `0x36aaa58` sends every option byte other than 1 to
`0x36aaab7`. That path appends zero and reaches the second variant test
at `0x36aaad9`, bypassing the 20-byte source loads and copy. The option-one
path copies those bytes and tests the variant at `0x36aaaaf`. Both tests
append the extra zero and big-endian u64 only when the variant dword is 1.

| Source byte `+0x18` | Source dword `+0x00` | Appended bytes |
| --- | --- | ---: |
| other than 1 | other than 1 | 9 |
| other than 1 | 1 | 18 |
| 1 | other than 1 | 29 |
| 1 | 1 | 38 |

These are suffix lengths. Under the stated helper/memory premises, a
helper-produced prefix of length L yields L plus the listed byte count.
No original type validity is assigned to arbitrary raw option encodings.

Tag byte: the result string is a fresh 1-byte allocation holding `0x61`
when the low byte of the tag argument (`edx`, saved into `ebp`) equals 3,
and `0x62` otherwise. The Python `tag_byte` model is scoped to admitted
u8 tags. Later caller-tag packets establish byte narrowing on their
measured dispatcher paths; this is not an all-u32 Python model claim.

Result record: qword `1` at `+0x00`, the tag-string pointer at `+0x08`,
qword `1` (length) at `+0x10`, the assembled 32 bytes at `+0x18`, the
constant `0x539` at `+0x38`, and zeros from `+0x40` through `+0x58`.

Boundary consumers: caller_a (`0x36aadf0`) writes result word `0x007e` on
one post-processing branch and `0x01a2` on the other; caller_b
(`0x36aaf10`) reaches the same `Result::unwrap()` panic message on its
discriminant-1 branch. Both are retained as boundary evidence only.

## Boundary

The suffix relation assumes valid disjoint input/output memory, stable
source fields and normally returning growth helpers that preserve the
live prefix, length and source record. It does not close allocation failure,
growth, diagnostic or unwind behavior. The initial helper's serialized
prefix and its length remain unknown.

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
