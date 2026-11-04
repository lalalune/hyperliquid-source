# RE-002: the dispatcher 0x400-exit body traced — a fourth form of the same ChaCha block function, legacy-encoded like the SSSE3 form but with an SSE4.1 (pinsrd) counter construction; identical counter/output contract to the SSSE3, AVX and AVX2 forms

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the CPU-feature dispatcher that the F2
  trace (PR #2749) pinned.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: the sign-exit packet (RE-002-node115-dispatcher-sign-exit)
  traced the dispatcher's sign-bit exit body `0x5bbb630` (the
  AVX2 form of the ChaCha block function) and left as its next
  question, verbatim: "trace the dispatcher's `0x400`-exit body
  at `0x5bb9a60..0x5bba11a` (1,722 bytes) — the last untraced
  feature exit — and name its operation: whether it is a
  fourth form of the same ChaCha block function, and how its
  counter/output contract compares to the SSSE3, AVX and AVX2
  forms now pinned."

## Answer

**It is a fourth form of the same ChaCha block function —
legacy-encoded like the SSSE3 form, but with its counter rows
built by `pinsrd` (SSE4.1), the construction the AVX form
uses. Its counter/output contract is identical to the SSSE3
(F2), AVX and AVX2 forms in every observable respect.**
Traced in full at its sole placement `0x5bb9a60..0x5bba11a`
(1,722 bytes, 324 instructions, SHA-256
`24663d382ee225bf024a091df6fcf0293aaa29a6059c320ef321561f4c4e46f0`;
the FDE span governs):

- the constants name the operation, and they are the narrower
  forms' own: the 16-byte ASCII string `"expand 32-byte k"` at
  `0x4519c0` (the ChaCha sigma row, referenced at `0x5bb9ae0`
  and `0x5bb9fa6`), its exact per-word double at `0x456c50`
  (the zero-round path, `0x5bb9fe5`), and the two `pshufb`
  masks (`0x4531c0` rotate-by-8, referenced twice in the loop;
  `0x452ec0` swap pattern, once) — the same four constants
  with the same reference pattern as the SSSE3 and AVX forms.
  The AVX2 form is the odd one out here: it reads 32-byte
  two-lane constants and never references the doubled sigma.
- the round loop (head `0x5bb9b40`, back edge `jne` at
  `0x5bb9fa0` after `dec esi` at `0x5bb9f9e`, 214
  instructions) is the ChaCha quarter-round network, and its
  rotation census is **identical** to the F2/AVX loop census:
  32 `paddd`, 32 `pxor`, 16 `pshufb`, rotations 16
  (`pshuflw`/`pshufhw 0xb1`, 8+8), 12 (`psrld 0x14` /
  `pslld 0xc`, 8+8), 8 (`pshufb`) and 7 (`psrld 0x19` /
  `pslld 0x7`, 8+8), with `pshufd` lane rotations
  `0x39`/`0x4e`/`0x93` at 8/8/4. The AVX2 form's census is
  exactly half of this at twice the width. One loop iteration
  runs two double rounds; `esi` is the iteration count, so the
  caller chooses the round count — exactly as in the other
  forms.
- the entry (`sub rsp,0x28`, no calls anywhere in the body)
  reads the same bytes `0x00..0x30` of the record at `rdi`
  (three 16-byte rows at `[rdi]`, `[rdi+0x10]`, `[rdi+0x20]`)
  and builds the same four counter rows from the 64-bit
  counter word at `[rdi+0x20]` (+0/+1/+2/+3, `lea` at
  `0x5bb9a77`/`0x5bb9a8f`/`0x5bb9aaa`) — here each variant row
  is the loaded counter/nonce row with its first two dwords
  replaced by the variant counter via a `pinsrd` pair (low
  dword from the `lea` result, high dword from its
  `shr 0x20`), where the SSSE3 form builds its rows with
  `movd` and shuffle/or merging and contains no `pinsrd` at
  all. Measured `pinsrd`-family counts across the four
  bodies: SSSE3 form 0, this form 8 `pinsrd`, AVX form 8
  `vpinsrd`, AVX2 form 8 `vpinsrd`.
- the epilogue (merge `0x5bba03b`) is the same ChaCha
  feed-forward in the F2/AVX arrangement: the constant rows
  receive their sigma add just after the loop (four adds,
  `0x5bb9faf..0x5bb9fc4`), the other rows are added to the
  entry-saved initial rows in the shared epilogue (12 adds),
  the result is stored as 16 vector stores covering 256 bytes
  at `rdx` (four 64-byte blocks; 15 `movdqu` and one `movups`
  at `+0xc0`), and the counter row is rebuilt with the
  counter advanced by 4 (`add rax,0x4` at `0x5bba03b`) and
  stored back at `[rdi+0x20]` (`0x5bba059`). The body ends in
  `ret` after `add rsp,0x28`; it has exactly three branches,
  all internal.
- with `esi == 0` (`test esi,esi` at `0x5bb9ac5`, `je` at
  `0x5bb9ada`) no round runs and the output is exactly
  initial + initial, via the doubled sigma at `0x456c50`.
  The full 256 bytes are still written and the counter still
  advances by 4 — again exactly as in the F2/AVX forms.

**What separates this form.** The encoding is the SSSE3
form's — every instruction is legacy-encoded (no VEX prefix
anywhere, no `ymm` operand, no `vzeroupper`) — but the
instruction floor is one feature step higher: `pshufb`
(SSSE3) for the rotate-by-8 step, as in F2, plus `pinsrd`
(SSE4.1) for the counter construction, which F2 does not
use. The dispatcher tests `0x400` after `0x4000` and before
bit 9, so the four exits now read as a strict feature
ladder: AVX2 (sign) → AVX (`0x4000`) → SSE4.1 (`0x400`) →
SSSE3 (bit 9), over the dispatcher's inline SSE2 clear arm.
In size this form sits next to F2 — 1,722 bytes / 324
instructions against F2's 1,758 / 340, with a 214-instruction
loop against 217 — and its frame is the smallest of the
framed forms: `0x28` bytes against F2's `0x38` and the AVX
form's `0x68` (the AVX2 form has no frame). Part of the
transposed state is stack-resident through the loop — the
four slots `[rsp-0x80]..[rsp-0x50]` are loaded and stored
inside the loop (22 of the body's 45 stack accesses) — but
that is a family trait of the 128-bit forms, not a
distinguisher: F2 (11 slots, 24 in-loop accesses) and the AVX
form (14 slots, 34) share it, and only the AVX2 form keeps
its state in registers (one red-zone slot, no in-loop
access). The six remaining slots of this body
(`[rsp-0x40]..[rsp+0x10]`) each hold one initial row: stored
once before the loop, loaded once in the epilogue.

**Selection.** The dispatcher `0x5bba800..0x5bbb030` tests
the cached feature word (slot `0x64dfa60`) in the order
sign, `0x4000`, `0x400`, bit 9. The `0x400` tests are at
`0x5bba84c` and (on the refresh-retry path) `0x5bbafe0`; the
exit block at `0x5bbafeb` unwinds the dispatcher frame
(`add rsp,0xa8`, four pops) and jumps at `0x5bbaff8` into
`0x5bb9a60` with the dispatcher's own caller arguments
(`rdi`, `esi`, `rdx`), so this body's `ret` returns straight
to that caller. A validated census of every direct E8/E9
transfer in `.text` finds exactly this one jump to the body,
and no call.

## Exact scope

| Role | Count |
| --- | ---: |
| bodies traced in full | 1 (`0x5bb9a60`, 1,722 bytes, 324 insns) |
| comparison bodies re-traced for the shared contract points | 3 (F2 `0x5bba120`, AVX form `0x5bbb030`, AVX2 form `0x5bbb630`, all hash-pinned) |
| loop rotation census vs F2/AVX | identical (all 10 counts) |
| loop rotation census vs AVX2 | exactly double (at half the width) |
| ymm operands / VEX-prefixed insns in the traced body | 0 / 0 |
| direct transfers to the traced body validated | 0 calls, 1 jump (the `0x400` exit jump) |
| dispatcher exits re-pinned | 4 of 4 |

## Stage 1 — body pin

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone:
the body's FDE range via `readelf` (135,313 FDEs; the traced
body's FDE is exactly `0x5bb9a60..0x5bba11a`), its byte
SHA-256 through the section table, and its instruction count
by fresh `objdump` disassembly. Any mismatch fails the
producer closed. All three comparison bodies are hash-pinned
the same way (F2 `e787f6af…`, 1,758 bytes, 340 instructions;
AVX form `c04bc82e…`, 1,530 bytes, 301 instructions; AVX2
form `963fe9ac…`, 868 bytes, 173 instructions).

## Stage 2 — the trace of 0x5bb9a60

- Entry and counter construction (`0x5bb9a60..0x5bb9ac5`, up
  to the gate): the three record rows are loaded, the counter
  word is taken into `rax`, the +1/+2/+3 variant rows are
  built with `lea`/`pinsrd`/`shr 0x20` groups, and
  `test esi,esi` gates the zero-round path (three initial-row
  saves sit between the `test` at `0x5bb9ac5` and the `je` at
  `0x5bb9ada`; `movdqa` stores do not touch the flags). The
  body's only external references are the four `.rodata`
  constants (`0x4519c0`, `0x452ec0`, `0x4531c0`, `0x456c50`),
  read through the section table; there are no callees.
- Round loop (`0x5bb9b40..0x5bb9fa0`, 214 instructions): two
  double rounds per iteration — column quarter rounds then
  diagonal quarter rounds, the diagonalisation done with
  `pshufd` `0x39`/`0x4e`/`0x93` lane rotations and the second
  double round's shuffle taken through the `0x452ec0` mask.
  Rotation census in `records.json` (`trace.round_loop`):
  32 `paddd`, 32 `pxor`, 16 `pshufb`, 8 each of the
  16/12/7 rotation pairs — the F2/AVX census exactly.
  `dec esi` at `0x5bb9f9e` and the `jne` back edge at
  `0x5bb9fa0` close the loop.
- Post-loop and zero-round paths: both join the epilogue at
  `0x5bba03b` — the loop path via the `jmp` at `0x5bb9fe3`
  after the four sigma adds and the initial-row reloads, the
  zero-round path by falling through from `0x5bb9fe5` with
  the doubled sigma loaded.
- Epilogue (`0x5bba03b..0x5bba119`): 12 `paddd` feed-forward
  adds, the counter write-back (the counter row rebuilt by
  the body's second `pinsrd` pair), 16 output stores,
  `add rsp,0x28`, `ret`.

## Stage 3 — the dispatcher and the transfer census

The producer re-derives the dispatcher's structure from its
disassembly: the feature-slot load, both `0x4000` test sites,
both `0x400` test sites, both bit-9 test sites, all four
exits in order (sign → `0x5bbb630`, `0x4000` → `0x5bbb030`,
`0x400` → `0x5bb9a60`, bit 9 → `0x5bba120`), and the `0x400`
exit block's unwind shape. The transfer census scans every
E8/E9 byte hit in `.text` whose relative target is the traced
body and validates each hit against the disassembly of its
containing FDE (a hit must be an instruction boundary
transferring to the target). The validated result is exactly
one jump — the `0x400` exit jump `0x5bbaff8` — and no call.
With this packet, all four dispatcher exits are traced.

## Explicit boundary and next question

What is **not** established: how the cached feature word
itself is computed — the refresh path behind slot `0x64dfa68`
that the dispatcher calls when a test finds the word
uninitialised, and therefore which cpuid leaves and bits the
four test bits (sign, `0x4000`, `0x400`, bit 9) are built
from (bit 9 is cpuid leaf 1 ecx bit 9, SSSE3, per the #2616
driver table; the other three mappings are inferred from the
traced bodies' instruction floors, not from the refresh
body); which indirect slot or table names the dispatcher (it
has no direct caller, per PR #2749's census); what
round-count values (`esi`) any caller passes, and therefore
which ChaCha variant (8/12/20) any given invocation computes;
who consumes the 256 output bytes downstream; and any runtime
values.

Next question: trace the feature-word refresh body reached
through slot `0x64dfa68` (called from the dispatcher's four
refresh sites) and pin how each tested bit of the cached
feature word at slot `0x64dfa60` — sign, `0x4000`, `0x400`
and bit 9 — is computed from the processor's feature leaves,
closing the dispatcher's last untraced piece.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/dispatcher_400_exit_static.py --output research/work-items/RE-002-node115-dispatcher-400-exit
python3 -B -m unittest discover -s tests -p test_dispatcher_400_exit_static.py -v
(cd research/work-items/RE-002-node115-dispatcher-400-exit && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x5bb9a60` (the
re-derived body hash no longer matches its pin), one byte of
the sigma constant at `0x4519c0` (the traced constants no
longer name the operation), one byte inside the F2 comparison
body `0x5bba120` (its hash pin no longer matches), and the low
byte of the `0x400` exit jump's rel32 at `0x5bbaff8` (the
dispatcher exit pins no longer match). These are checks of
the named obligations — the body pin, the constant identity,
the comparison pins and the selection pins — not target
execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
