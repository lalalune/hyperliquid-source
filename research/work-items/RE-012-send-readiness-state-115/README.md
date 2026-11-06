# RE-012: send-helper result and generation-checked readiness updates

- Component: network transport / APIs, gossip and startup; task RE-012.
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: what does the raw helper called by the prepared-write loop return,
  and when does it modify the shared readiness word or retry readiness?
- Status: static instruction observations and an explicitly conditional scalar
  interpretation; no execution, reconstructed Rust, or component gate claim.

## Gap closed and prior work

The retained `RE-012-write-progress-115` packet / PR #2166 implements its caller's
conditional progress kernel. It exports this helper as context, but explicitly
leaves helper readiness, send, retry and CAS semantics open. This packet resolves
that bounded helper's result paths and two distinct state-update paths. It does
not re-claim the caller, its counter charge, or its resume tables.

Before selection, live GitHub searches for `5cdfc90`, `send readiness`, and
open `send` contributions were inspected on 2026-11-05. PR #2974 mentions this
helper to distinguish it from signal wake writers; it does not recover its state
machine. PR #2996 covers writev and PR #3047 covers recv: their related retry
policy is context, not ownership of this send body. The local research search
found the retained caller packet and its references/integration records. Search
absence is not a guarantee of exclusive ownership.

## Original evidence

All addresses are linked ELF virtual addresses, with no guessed rebase. The
complete FDE-described interval is `[0x5cdfc90, 0x5cdfe4b)`, 443 bytes / 120
Capstone instructions. Body file offset is `0x5cdec90`; its SHA-256 is
`df885a621985a5dae8f50e02efbadea04d1cd6036db2a7408b74eb4b7b22e807`.
`records.json` retains the complete bytes, actual FDE/CIE records, all 22 direct
branches, all seven calls and each RIP-relative call-slot relocation.
`disassembly.txt` contains the complete decoded interval. Every direct branch
destination is a decoded instruction boundary inside this interval. Unwind
extent and linear decoding alone do not prove all possible runtime entries.

The two readiness calls (`0x5cdfcc1`, `0x5cdfd08`) use the same relocation-backed
slot `0x64e14d8`, with R_X86_64_RELATIVE addend `0x5cf22f0`. Their selected mode
argument is ECX=1. Their output record is on the stack: qword +0, byte +8 and
tag byte +9. Original source types/names for this record remain unknown.

The `send` call at `0x5cdfd3e` resolves through the unique symbol relocation at
slot `0x64eb088`. Arguments are the fd sampled from owner+0x18 before the first
readiness call, the input pointer, the requested length, and flags `0x4000`.
No live socket is used. Errno is loaded through the unique `__errno_location`
binding at slot `0x64dffc8` and packed as `(u32(errno) << 32) | 2`.

## Conditional result contract

The ordinary return is a raw pair RAX/RDX, not an asserted Rust Result ABI.

| Selected condition | Raw result and continuation |
| --- | --- |
| readiness tag 3 | RAX=2; no send; payload is unspecified |
| readiness tag 2 | RAX=1, RDX=readiness qword; no send |
| sampled fd is -1 and readiness tag is neither 2 nor 3 | terminal call through slot `0x64df830`, addend `0x1680c10`; no send |
| send returns anything other than -1 | RAX=0, RDX=actual return value; short positive results take the state-update path below |
| send returns -1, classifier `0x5cdf1b0` returns a byte other than 0x0d | RAX=1, RDX=packed errno |
| send returns -1, classifier returns 0x0d | generation-checked state update, opaque helper `0x5cdf710`, then readiness again |

At initial tag-3 admission, R12 has not been assigned from the stack record,
so no valid payload claim follows from the move through R12. Consumers should
not read a meaningful pending payload from this observation. The retry route
does not immediately call send again: it re-enters the readiness helper first.
Classifier byte `0x0d` is an observed return value; mapping that classification
to every platform errno and recovering the classifier are separate work.

## State update and arithmetic widths

Let S be the readiness qword at stack+0, G the byte at stack+8, and W the shared
qword loaded from state+0x90. The instruction sequence computes a mask
`M = (S & 0x33) ^ 0x00ff003f`. The initial AND writes R12D, so the upper half of
R12 is zero. The desired CAS value is **zero-extended** `u32(W) & u32(M)`.
It is not the full-width expression `W & ~S` and does not preserve arbitrary
upper bits. The equivalent bit-field expression is
`(W & 0x00ff0000) | (W & 0x3f & ~(S & 0x33))`.

Both loops compare G with `u8(W >> 16)` before a locked 64-bit CMPXCHG. A
generation mismatch skips the store. A CAS failure reloads W through RAX and
rechecks its generation before attempting another write. This describes
instructions, not an atomic memory-ordering or absence-of-races proof.

The retry/error loop at `0x5cdfd80` uses the state pointer cached from owner+0x10
after initial readiness admission. It rejoins the opaque helper and readiness
on both a generation mismatch and a successful clear. In contrast, the success
loop at `0x5cdfde0` reloads owner+0x10 after send and returns the successful byte
count after either outcome. This distinction matters if helper calls can change
owner+0x10; preservation and aliasing remain open.

Success attempts the update only when `0 < actual < requested` under the native
unsigned comparison. Zero, equality and overcount all skip the clear. This
records even overcount behavior without asserting that a conforming send can
produce it. An empty request is not pre-filtered by this helper.

## Reproduction and controls

Python 3.12.14, Capstone 5.0.6, pyelftools 0.32; Windows x86-64 host. Dependencies
were installed from PyPI in ignored `work/python-deps`. From the repository root,
with these dependencies on Python's module path:

```sh
python research/work-items/RE-012-send-readiness-state-115/verify.py --write
python research/work-items/RE-012-send-readiness-state-115/verify.py
```

The first command regenerates the two evidence exports; the second requires
byte-for-byte equality with both retained files. A full target SHA-256 guard
runs before extracting evidence. Neither command executes or interprets any
captured instruction, opens a socket, or invokes the external helpers.

Seven operative mutations (pending tag, send flags, retry branch condition,
readiness mask, XOR immediate, short-send predicate, second mask) are rejected
with whole-file authentication deliberately disabled in that control only.
These controls check that the observations actually bind those instructions;
they do not prove the surrounding prose. Two separately expressed mask
calculations agree over 65,536 finite cases, including full-width words. This
is an arithmetic cross-check, not observed network or concurrency behavior.

See `validation.md` for repository checks and their actual limits.

## Remaining gaps and next step

No source types, original function name, exact dependency version, allocation
or ownership proof, external-helper implementation, complete caller census,
panic/unwind behavior, runtime equivalence, compiled Rust comparison or binary
coverage increase is claimed. No acceptance gate or byte-window registration
changes. New notes and verifier are independently authored under the repository
MIT license; original captured bytes retain their existing rights.

Next: recover the mode-1 readiness producer at `0x5cf22f0`, particularly the
meaning and lifetime of its sampled generation byte, before implementing the
helper as a complete transport primitive.
