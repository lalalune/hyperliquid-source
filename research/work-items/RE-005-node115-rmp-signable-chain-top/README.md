# RE-005: node 115 `rmp_signable` chain top — who calls grand_a, how grand_b is reached, and which tag values those sites pass

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for both dispatcher censuses, the
  grand_b slot binding and its single consumer, and the tag-argument
  provenance at both reaching sites, all re-derived from the pinned
  target bytes by the checker; **unresolved** for every naming or
  semantic claim listed under the boundary.

## The bounded question

The `rmp_signable` caller-tag packet (RE-005-node115-rmp-signable-caller-tags)
established that the serializer's tag is the zero-extended low byte of
each dispatcher's own entry `edx` on every reaching path, and left the
chain open one level higher: who calls grand_a (its one direct call
site is `0x37133b3`), how is grand_b reached (it has no `.text` call
site), and which third-argument values do those sites pass. That is
what this packet pins — finally grounding, at the top of the chain,
when the emitted tag byte is `0x61` and when it is `0x62`.

## Why this item

The operator action is answering the one question the caller-tag
packet explicitly leaves open. The basis for the expected behaviour
is the serializer's own contract: its emitted byte stream differs by
exactly this one byte (the serializer packet's claim), so a
reconstruction of the signing payload must know which tag values
actually occur. The loss when it is wrong is a payload whose tag byte
differs from the node's — a signature over different bytes.
Independence by repro case: the other open RE-005 packets cover the
bincode varint size-state (#2257), the bincode u64 reader state
(#2300), the `rmp_signable` `.rodata` census (#2311), the serializer
(#2399) and the caller tags (#2419); none traces the dispatchers' own
callers, the FDE containing `0x37133b3`, or grand_b's reachability.

## Exact scope

| role | FDE half-open range | bytes | body SHA-256 |
| --- | --- | ---: | --- |
| serializer | `0x36aa9a0..0x36aade6` | 1,094 | `18c066ea3b97c2de167b8e7557d1e3e3cdbbd2f757dd83a00eafc827718eca9d` |
| caller_a | `0x36aadf0..0x36aaf0e` | 286 | `d334db07754d3444527141f0c43ec5316b25cef9dac35cfdb48a6728d6052127` |
| caller_b | `0x36aaf10..0x36aaff6` | 230 | `98513eb74d9449bf469425940d4ae673921f4494e34133e938a9f4f37f324582` |
| grand_a | `0x36c2050..0x36c2f99` | 3,913 | `eaa2515d051afca85d5136bd3c53c7a6423abdb86d6832ef7b4d6132df182514` |
| grand_b | `0x36c5350..0x36c5676` | 806 | `19f158b96c98c1a4622032b450f29f35a8226cd2c17dea6fdd80ccc0a8f12662` |
| top | `0x3713300..0x3713523` | 547 | `823b4167a13a0cdd666fb07f12958004b36e0a3505083ff7a3550bcc425d743c` |
| top_caller | `0x3ebdd10..0x3ebdf64` | 596 | `450e90e2bbec1aaa4fd870446538c06ae1f658b267176b89f5fc7ef7c62dd62e` |
| grand_b_caller | `0x38d9c60..0x38d9edc` | 636 | `ce1931ed60cdd5707c385cc7341cf8ae64ae6f1f6baed83abb69116e6c1e156b` |

The first five body hashes are re-derived here and agree with the
caller-tag packet's pins; that packet's relied-upon links (the
serializer tag rule, both callers' forwarding prefixes, and the
dispatcher call census) are re-verified by this checker. Measured
denominators: the call and reference censuses below each cover the
whole `.text` (83,719,936 bytes), all 60,723 `.rela.dyn` entries, and
— for the raw census — the whole 105,896,032-byte file.

## Trace

1. Grand_a census. A full-`.text` E8/E9 scan finds exactly **one**
   direct call site to grand_a, at `0x37133b3` inside the top FDE
   (`0x3713300..0x3713523`), and no jump sites. No `.rela.dyn` entry
   references grand_a's start or any address inside its body, and
   grand_a's VA occurs nowhere in the file as raw data (8-byte or
   4-byte form).
2. Top FDE shape. The top FDE treats its third argument (`rdx`) as a
   three-qword container: it loads the range `[rdx]` (begin) and
   `[rdx+0x8]` (end), branches to its epilogue when the range is
   empty, and otherwise iterates the range with element stride
   `0x168`, calling grand_a once per element (loop-back branch at
   `0x371348d` to the loop head `0x3713360`).
3. Top tag provenance. At entry the FDE loads the container's third
   qword, `[rdx+0x10]`, and saves it to a frame slot (`0x3713329`,
   `0x371332d`; the checker pins that this slot is written and read
   exactly once each). At the loop head, on **every** iteration, it
   reloads that pointer (`0x3713360`), dereferences it (`0x3713365`),
   and loads its first byte into `edx` (`0x371336c`). The whole span
   from that load to the call at `0x37133b3` is pinned; no instruction
   in it writes `edx`, so the byte loaded is the third argument
   grand_a receives. The remaining arguments at the call are the out
   record on the caller's frame (`rdi`), the current element +0x10
   (`rsi`), a frame-assembled record (`rcx`) and the element +0x100
   (`r8`).
4. Grand_b census. Grand_b has **no** direct call or jump site in
   `.text`, no RIP-relative reference of any encoding this binary
   uses (ff 15 / ff 25 / REX.W mov/lea), and no raw VA occurrence
   except one: the addend field of a single `.rela.dyn` entry. That
   entry is an `R_X86_64_RELATIVE` relocation binding the `.got` slot
   `0x64e8ed0` to grand_b; the slot's file content is zero and is
   filled by the dynamic linker from that relocation. Exactly one
   instruction in the binary references the slot: the indirect call
   at step 5.
5. The reaching call. Inside the grand_b_caller FDE
   (`0x38d9c60..0x38d9edc`), the call `ff 15` at `0x38d9e07` invokes
   whatever the slot holds — grand_b, by step 4. The record argument
   (`rsi`) is the frame record at `[rsp+0x98]`; the out argument
   (`rdi`) and the assembled record argument (`rcx`) are frame
   addresses; the fifth argument (`r8`) is a saved frame qword.
6. Grand_b tag provenance. At the grand_b_caller entry, the byte at
   `[rsi+0x11d]` of its second argument is captured into `ebp`
   (`0x38d9c77`). Before the entry path split it is stored to the
   frame slot `[rsp+0xf]` (`0x38d9cc5`, right after an unrelated
   helper call whose boolean result selects between two setup arms);
   both arms converge at `0x38d9daa`, above the call. Immediately
   before the call, `edx` is reloaded from that slot (`0x38d9df0`).
   The capture, store and load patterns are each unique in the FDE
   body (count-pinned by the checker). So the third argument at
   grand_b's only reaching call is that record byte, unchanged.

## Result

Both dispatcher entries are now grounded. On each path the tag is a
single byte loaded from a caller-supplied record — no path in the
whole chain materialises a constant tag:

| reaching path | tag value at the dispatcher entry | emitted byte `0x61` exactly when |
| --- | --- | --- |
| top FDE `0x3713300` → call `0x37133b3` → grand_a | the byte at `[[arg3+0x10]]` (two dereferences of the top FDE's third argument), reloaded per element | that memory byte equals 3 at the call |
| grand_b_caller FDE `0x38d9c60` → indirect call `0x38d9e07` via `.got` slot `0x64e8ed0` → grand_b | the byte at `[arg2+0x11d]` of the calling FDE's second argument | that record byte equals 3 |

Any other source byte value delivers a non-3 tag and the emitted
byte is `0x62`. Which byte occurs for a given record is data: the
static chain fixes the source and the rule, not the runtime value.

## Boundary

The two FDEs above the reaching sites are recorded as boundary
evidence, not traced. The top FDE is itself called directly exactly
once, at `0x3ebdd9e` inside the top_caller FDE, which assembles the
three-qword container on its own stack immediately before the call
(field stores at `0x3ebdd80`, `0x3ebdd85`, `0x3ebdd8a`); where that
FDE's own values come from is not traced, and its five direct
callers are counted, not followed. The grand_b_caller FDE has no
direct call sites either: it is bound by its own `R_X86_64_RELATIVE`
relocation into `.got` slot `0x64e6c60` and consumed by 12 indirect
call sites, which are counted, not followed.

This packet does not name the record or object types the pointers
denote, does not say what the two source bytes mean, and does not
observe any runtime value. The dispatcher-internal dispatch (jump
tables, arms, the equality gate) is the caller-tag packet's claim,
re-anchored here only through the caller census, the forwarding
prefixes and the body hashes. The RIP-relative census covers the
encodings this binary uses for slot and pointer access (ff 15,
ff 25, REX.W mov/lea); it does not claim to enumerate every
conceivable encoding.

Next question: what the two tag source bytes denote — the object the
top FDE's container field +0x10 points through to, and the field at
+0x11d of the record the grand_b_caller FDE receives — and which
values they take for each action family in practice.

## Reproduce

```sh
python3 -B tools/rmp_signable_chain_top_static.py --output research/work-items/RE-005-node115-rmp-signable-chain-top
python3 -B -m unittest discover -s tests -p 'test_rmp_signable_chain_top_static.py' -v
cd research/work-items/RE-005-node115-rmp-signable-chain-top && sha256sum -c MANIFEST.sha256
```

The checker authenticates the pinned binary (size and SHA-256) before
any analysis, re-derives every value above from the target bytes,
validates each pinned address and every chain call site as a native
instruction start against GNU objdump output, and carries corruption
controls (mutated top tag load, tag pointer field, grand_b tag
capture and store, indirect-call displacement and relocation addend,
and a wrong public identity) that must all be rejected. It writes
only the packet directory, uses the Python standard library plus the
repository's own tools, and never executes the target.
