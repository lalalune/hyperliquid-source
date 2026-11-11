# RE-002: the dispatcher sign-bit exit body traced — the AVX2 (256-bit ymm) form of the same ChaCha block function as the SSSE3 and AVX forms, with an identical counter/output contract; it is the widest form, not a scalar or reduced one

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the CPU-feature dispatcher that the F2
  trace (PR #2749) pinned.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: PR #2754 traced the dispatcher's `0x4000`-exit
  body `0x5bbb030` (the AVX form of the ChaCha block function)
  and left as its next question, verbatim: "trace the
  dispatcher's sign-bit exit body at `0x5bbb630..0x5bbb994`
  (868 bytes) — the first feature exit in test order — and
  name its operation: whether it is a scalar (or otherwise
  reduced) form of the same ChaCha block function, and how
  its counter/output contract compares to the SSSE3 and AVX
  forms now pinned."

## Answer

**It is the same ChaCha block function, in its AVX2
(256-bit `ymm`) form — the widest of the dispatcher's three
traced forms, not a scalar or reduced one. Its
counter/output contract is identical to the SSSE3 (F2) and
AVX forms in every observable respect.** Traced in full at
its sole placement `0x5bbb630..0x5bbb994` (868 bytes, 173
instructions, SHA-256
`963fe9acf58718076c5a6fa97b4cfc297cd0b8d73719ac18d50b7242bf72a944`;
the FDE span governs):

- the constants name the operation, widened to two lanes:
  the 32-byte constant at `0x458660` is the ChaCha sigma
  row `"expand 32-byte k"` twice, once per lane (loaded at
  the loop entry `0x5bbb6a4` and on the zero-round path
  `0x5bbb87d`); the rotate-by-8 `vpshufb` mask at `0x458120`
  is the F2 form's 16-byte mask at `0x4531c0` duplicated per
  lane; the swap mask at `0x457ca0` is the F2 form's mask at
  `0x452ec0` in the low lane and that same mask with every
  byte raised by `0x10` in the high lane; and the epilogue
  adds the 16-byte sigma at `0x4519c0` itself (referenced at
  `0x5bbb8ae`). The doubled sigma at `0x456c50` that both
  narrower forms load on their zero-round paths is **not**
  referenced by this body.
- the round loop (head `0x5bbb6d0`, back edge `jne` at
  `0x5bbb85f` after `dec esi` at `0x5bbb85d`, 84
  instructions) is the ChaCha quarter-round network, and
  its rotation census is **exactly half** the F2/AVX loop
  census on every count: 16 `vpaddd`, 16 `vpxor`, 8
  `vpshufb`, rotations 16 (`vpshuflw`/`vpshufhw 0xb1`, 4+4),
  12 (`vpsrld 0x14` / `vpslld 0xc`, 4+4), 8 (`vpshufb`) and
  7 (`vpsrld 0x19` / `vpslld 0x7`, 4+4), with `vpshufd` lane
  rotations `0x39`/`0x4e`/`0x93` at 4/4/2. Each instruction
  works on 256 bits instead of 128, so the per-bit work is
  identical; the producer requires the doubled census to
  equal the F2/AVX census exactly. One loop iteration runs
  two double rounds; `esi` is the iteration count, so the
  caller chooses the round count — exactly as in the other
  forms.
- the entry (no stack frame at all — see below) reads the
  same bytes `0x00..0x30` of the record at `rdi`: the
  counter/nonce row as an `xmm` (`vmovdqa [rdi+0x20]` at
  `0x5bbb630`), the 64-bit counter word into `rax`
  (`0x5bbb635`), and bytes `0x00..0x20` / `0x10..0x30` as
  two overlapping 32-byte `ymm` loads (`0x5bbb675`,
  `0x5bbb679`). It builds the same four counter rows
  (+0/+1/+2/+3, `lea` at `0x5bbb639`/`0x5bbb64d`/`0x5bbb661`,
  six `vpinsrd`) as the AVX form, then fans the rows out to
  256-bit form with four `vinserti128` (`0x5bbb67e`,
  `0x5bbb684`, `0x5bbb68a`, `0x5bbb690`): the `[rdi]` and
  `[rdi+0x10]` rows are duplicated into both lanes (the
  same row serves all four blocks) while the counter rows
  pair up as [+0,+1] and [+2,+3] — two blocks per `ymm`
  register, the four blocks held as register pairs.
- the epilogue (merge `0x5bbb892`) is the same ChaCha
  feed-forward, organised differently: **all 16** `vpaddd`
  feed-forward adds sit in the shared epilogue (the
  constant rows' addend is the sigma row itself, loaded at
  `0x5bbb8ae`), where the narrower forms split them 4
  pre-merge + 12 in the epilogue. The result is stored as
  16 vector stores covering 256 bytes at `rdx` (four
  64-byte blocks), the high lanes pulled down with eight
  `vextracti128`, and the counter row is rebuilt with the
  counter advanced by 4 (`add rax,0x4` at `0x5bbb892`) and
  stored back at `[rdi+0x20]` (`0x5bbb8a9`). The body ends
  in `ret` after a `vzeroupper` at `0x5bbb990`; it has
  exactly three branches, all internal, and no calls.
- with `esi == 0` (`test esi,esi` at `0x5bbb696`, `je` at
  `0x5bbb698`) no round runs and the output is exactly
  initial + initial: the zero-round path at `0x5bbb87d`
  loads the two-lane sigma constant (the plain sigma row
  duplicated per lane — not the doubled sigma) and
  pre-loads the remaining worked rows with the initial
  rows, so the epilogue's adds complete the doubling. The
  full 256 bytes are still written and the counter still
  advances by 4 — again exactly as in the other forms.

**Why it is not a scalar or reduced form.** The round loop
works entirely on 256-bit `ymm` registers (110 of the body's
173 instructions name a `ymm` operand) — wider than either
comparison form (the SSSE3 form is legacy-SSE `xmm`, the AVX
form is VEX-encoded but still `xmm`-only, with zero `ymm`
operands). The four-block parallelism is unchanged; what
changes is that each register carries two blocks. That is
also why this form is the *shortest* of the three: 868
bytes / 173 instructions against the AVX form's 1,530 / 301
and the SSSE3 form's 1,758 / 340, with an 84-instruction
loop against 189 and 217. Further corollaries of the AVX2
form: no stack frame at all (the SSSE3 form takes `0x38`
bytes, the AVX form `0x68`) — the sole stack access is a
red-zone save of the +3 counter row at `[rsp-0x18]`
(`0x5bbb69e`), restored at `0x5bbb875`, because `xmm15` is
needed as a loop temporary; and 32-byte two-lane constants
where the narrower forms read the 16-byte originals.

**Selection.** The dispatcher `0x5bba800..0x5bbb030` tests
the cached feature word (slot `0x64dfa60`) in the order
sign, `0x4000`, `0x400`, bit 9 — the sign exit is the first
test in that order. The sign exit block at `0x5bbaf85`
unwinds the dispatcher frame (`add rsp,0xa8`, four pops)
and jumps at `0x5bbaf92` into `0x5bbb630` with the
dispatcher's own caller arguments (`rdi`, `esi`, `rdx`),
so this body's `ret` returns straight to that caller. A
validated census of every direct E8/E9 transfer in `.text`
finds exactly this one jump to the body, and no call.

## Exact scope

| Role | Count |
| --- | ---: |
| bodies traced in full | 1 (`0x5bbb630`, 868 bytes, 173 insns) |
| comparison bodies re-traced for the shared contract points | 2 (F2 `0x5bba120`, AVX form `0x5bbb030`, both hash-pinned) |
| loop rotation census vs F2/AVX | exactly half on all 10 counts (2× width) |
| ymm instructions in the traced body | 110 |
| direct transfers to the traced body validated | 0 calls, 1 jump (the sign exit jump) |
| dispatcher exits re-pinned | 4 of 4 |

## Stage 1 — body pin

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone:
the body's FDE range via `readelf` (135,313 FDEs; the traced
body's FDE is exactly `0x5bbb630..0x5bbb994`), its byte
SHA-256 through the section table, and its instruction count
by fresh `objdump` disassembly. Any mismatch fails the
producer closed. Both comparison bodies are hash-pinned the
same way (F2 `e787f6af…`, 1,758 bytes, 340 instructions; AVX
form `c04bc82e…`, 1,530 bytes, 301 instructions).

## Stage 2 — the trace of 0x5bbb630

- Entry and fan-out (`0x5bbb630..0x5bbb696`, up to the
  gate): the counter/nonce row is loaded as an `xmm`, the
  counter word is taken into `rax`, the +1/+2/+3 variant
  rows are built with `lea`/`vpinsrd`/`shr 0x20` groups
  (the AVX form's construction), the two record rows are
  loaded as 32-byte `ymm` loads, and four `vinserti128`
  build the 256-bit state: key rows duplicated per lane,
  counter rows paired [+0,+1] and [+2,+3]. `test esi,esi`
  gates the zero-round path. The body's only external
  references are the four `.rodata` constants
  (`0x458660`, `0x458120`, `0x457ca0`, `0x4519c0`), read
  through the section table; there are no callees.
- Pre-loop (`0x5bbb69e..0x5bbb6c9`): the +3 counter row is
  saved to the red zone, the three 32-byte constants are
  loaded (`ymm12`, `ymm10`, `ymm11`), and the pair partners
  are copied (`ymm8 = ymm12`, `ymm14 = ymm6`, `ymm15 =
  ymm7`).
- Round loop (`0x5bbb6d0..0x5bbb85f`, 84 instructions): two
  double rounds per iteration — column quarter rounds then
  diagonal quarter rounds, the diagonalisation done with
  `vpshufd` `0x39`/`0x4e`/`0x93` lane rotations. The census
  (in `records.json`, `trace.round_loop`) is exactly half
  the F2/AVX census on every count; the producer re-derives
  all three censuses from the binary and requires the
  doubled sign census to equal the F2/AVX census.
- Post-loop and zero-round paths: both join the epilogue at
  `0x5bbb892` — the loop path via the register re-pairing
  at `0x5bbb865..0x5bbb875` (including the red-zone restore
  of the +3 counter row) and the `jmp` at `0x5bbb87b`, the
  zero-round path by falling through from `0x5bbb87d` with
  the two-lane sigma loaded and the worked rows pre-loaded
  with the initial rows.
- Epilogue (`0x5bbb892..0x5bbb993`): the counter write-back
  first (`rax += 4`, the counter/nonce row rebuilt by a
  `vpinsrd` pair and stored at `[rdi+0x20]`), then 16
  `vpaddd` feed-forward adds interleaved with 16 output
  stores and eight `vextracti128` lane extracts,
  `vzeroupper`, `ret`.

## Stage 3 — the dispatcher and the transfer census

The producer re-derives the dispatcher's structure from its
disassembly: the feature-slot load, the two `0x4000` test
sites, all four exits in order (sign → `0x5bbb630`,
`0x4000` → `0x5bbb030`, `0x400` → `0x5bb9a60`, bit 9 →
`0x5bba120`), and the sign exit block's unwind shape. The
transfer census scans every E8/E9 byte hit in `.text` whose
relative target is the traced body and validates each hit
against the disassembly of its containing FDE (a hit must
be an instruction boundary transferring to the target).
The validated result is exactly one jump — the sign exit
jump `0x5bbaf92` — and no call.

## Explicit boundary and next question

What is **not** established: the operation of the
dispatcher's one remaining untraced exit — the `0x400`
exit body at `0x5bb9a60` (FDE `0x5bb9a60..0x5bba11a`,
1,722 bytes; an older boundary note's 442-byte figure is
superseded by the FDE span), whose address and FDE span
are pinned here and in PRs #2749/#2754 but whose operation
is not traced; which indirect slot or table names the
dispatcher (it has no direct caller, per PR #2749's
census); what round-count values (`esi`) any caller
passes, and therefore which ChaCha variant (8/12/20) any
given invocation computes; who consumes the 256 output
bytes downstream; and any runtime values.

Next question: trace the dispatcher's `0x400`-exit body at
`0x5bb9a60..0x5bba11a` (1,722 bytes) — the last untraced
feature exit — and name its operation: whether it is a
fourth form of the same ChaCha block function, and how its
counter/output contract compares to the SSSE3, AVX and
AVX2 forms now pinned.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/dispatcher_sign_exit_static.py --output research/work-items/RE-002-node115-dispatcher-sign-exit
python3 -B -m unittest discover -s tests -p test_dispatcher_sign_exit_static.py -v
(cd research/work-items/RE-002-node115-dispatcher-sign-exit && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x5bbb630` (the
re-derived body hash no longer matches its pin), one byte of
the sigma constant at `0x4519c0` (the traced constants no
longer name the operation), one byte inside the F2 comparison
body `0x5bba120` (its hash pin no longer matches), and the low
byte of the sign exit jump's rel32 at `0x5bbaf92` (the
dispatcher exit pins no longer match). These are checks of
the named obligations — the body pin, the constant identity,
the comparison pins and the selection pins — not target
execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
