# RE-002: the dispatcher 0x4000-exit body traced — the AVX (VEX-encoded) form of the same ChaCha block function as the SSSE3 F2 body, at the same 128-bit width and with an identical counter/output contract

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the CPU-feature dispatcher that the F2
  trace (PR #2749) pinned.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: PR #2749 traced the bit-9 set-arm body `0x5bba120`
  (the SSSE3 form of the ChaCha block function) and left as its
  next question, verbatim: "trace the dispatcher's `0x4000`-exit
  body at `0x5bbb030..0x5bbb62a` — the next feature exit in test
  order after bit 9 — and name its operation: whether it is the
  same ChaCha block function at a wider vector form, and how its
  counter/output contract compares to the F2 body's."

## Answer

**It is the same ChaCha block function, in its AVX
(VEX-encoded) form — not a wider-vector form. Its
counter/output contract is identical to the F2 body's in every
observable respect.** Traced in full at its sole placement
`0x5bbb030..0x5bbb62a` (1,530 bytes, 301 instructions, SHA-256
`c04bc82ee291c06eb8e65fe73d86dd880a11f4ff06aec15c62956a579b916892`;
the FDE span governs — the 1,522-byte figure in the F2 packet's
boundary note is 8 bytes short of it):

- the constants name the operation, and they are the F2 body's
  own: the 16-byte ASCII string `"expand 32-byte k"` at
  `0x4519c0` (the ChaCha sigma row, referenced at `0x5bbb08a`
  and `0x5bbb4b3`), its exact per-word double at `0x456c50`
  (the zero-round path, `0x5bbb503`), and the two `vpshufb`
  masks (`0x4531c0` rotate-by-8, referenced twice in the loop;
  `0x452ec0` swap pattern, once) — the same four references
  with the same pattern as the SSSE3 form.
- the round loop (head `0x5bbb100`, back edge `jne` at
  `0x5bbb4ad` after `dec esi` at `0x5bbb4ab`, 189 instructions)
  is the ChaCha quarter-round network, and its rotation census
  is **identical** to the F2 loop's: 32 `vpaddd`, 32 `vpxor`,
  16 `vpshufb`, rotations 16 (`vpshuflw`/`vpshufhw 0xb1`, 8+8),
  12 (`vpsrld 0x14` / `vpslld 0xc`, 8+8), 8 (`vpshufb`) and 7
  (`vpsrld 0x19` / `vpslld 0x7`, 8+8), with `vpshufd` lane
  rotations `0x39`/`0x4e`/`0x93` at 8/8/4. One loop iteration
  runs two double rounds; `esi` is the iteration count, so the
  caller chooses the round count — exactly as in the F2 body.
- the entry (`sub rsp,0x68`, no calls anywhere in the body)
  reads the same bytes `0x00..0x30` of the record at `rdi`
  (three 16-byte rows at `[rdi]`, `[rdi+0x10]`, `[rdi+0x20]`)
  and builds the same four counter rows from the 64-bit
  counter word at `[rdi+0x20]` (+0/+1/+2/+3, at
  `0x5bbb041`/`0x5bbb05a`/`0x5bbb06e`) — here each variant row
  is the loaded counter/nonce row with its first two dwords
  replaced by the variant counter via a `vpinsrd` pair (low
  dword from the `lea` result, high dword from its `shr 0x20`),
  where the SSSE3 form builds its rows with `movd` and
  shuffle/or merging.
- the epilogue (merge `0x5bbb55b`) is the same ChaCha
  feed-forward: the constant rows receive their sigma add just
  after the loop (four adds, `0x5bbb4bb..0x5bbb4ce`), the other
  rows are added to the entry-saved initial rows in the shared
  epilogue (12 adds), the result is stored as 16 vector stores
  covering 256 bytes at `rdx` (four 64-byte blocks), and the
  counter row is rebuilt with the counter advanced by 4
  (`add rax,0x4` at `0x5bbb55b`) and stored back at
  `[rdi+0x20]` (`0x5bbb572`). The body ends in `ret` after a
  `vzeroupper`; it has exactly three branches, all internal.
- with `esi == 0` (`test esi,esi` at `0x5bbb082`, `je` at
  `0x5bbb084`) no round runs and the output is exactly
  initial + initial, via the doubled sigma at `0x456c50`. The
  full 256 bytes are still written and the counter still
  advances by 4 — again exactly as in the F2 body.

**Why it is not a wider-vector form.** Every vector
instruction in the body is VEX-encoded (`vpaddd`, `vpxor`,
`vpshufb`, `vmovdqa`, `vpinsrd`, …; 282 of 301 instructions
carry the `v` prefix, the rest are scalar), but every vector
register operand is a 128-bit `xmm` register — **no `ymm`
operand occurs anywhere in the body**. The width and the
four-block parallelism are therefore unchanged from the SSSE3
form; what the `0x4000` feature bit buys is the encoding:
three-operand non-destructive forms (hence 301 instructions
in 1,530 bytes against the SSSE3 form's 340 in 1,758, and a
189-instruction loop against 217 — the saved instructions are
the destructive form's register copies), `vpinsrd` counter
construction, a `0x68`-byte frame against `0x38`, and a
`vzeroupper` at `0x5bbb622` before `ret`.

**Selection.** The dispatcher `0x5bba800..0x5bbb030` tests the
cached feature word (slot `0x64dfa60`) in the order sign,
`0x4000`, `0x400`, bit 9. The `0x4000` tests are at
`0x5bba835` and (on the refresh-retry path) `0x5bbafad`; the
exit block at `0x5bbafb8` unwinds the dispatcher frame
(`add rsp,0xa8`, four pops) and jumps at `0x5bbafc5` into
`0x5bbb030` with the dispatcher's own caller arguments
(`rdi`, `esi`, `rdx`), so this body's `ret` returns straight
to that caller. A validated census of every direct E8/E9
transfer in `.text` finds exactly this one jump to the body,
and no call.

## Exact scope

| Role | Count |
| --- | ---: |
| bodies traced in full | 1 (`0x5bbb030`, 1,530 bytes, 301 insns) |
| comparison bodies re-traced for the shared contract points | 1 (F2, `0x5bba120`, hash-pinned) |
| loop rotation census vs F2 | identical (all 10 counts) |
| ymm operands in the traced body | 0 |
| direct transfers to the traced body validated | 0 calls, 1 jump (the `0x4000` exit jump) |
| dispatcher exits re-pinned | 4 of 4 |

## Stage 1 — body pin

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone:
the body's FDE range via `readelf` (135,313 FDEs; the traced
body's FDE is exactly `0x5bbb030..0x5bbb62a`), its byte
SHA-256 through the section table, and its instruction count
by fresh `objdump` disassembly. Any mismatch fails the
producer closed. The F2 comparison body is hash-pinned the
same way (`e787f6af…`, 1,758 bytes, 340 instructions).

## Stage 2 — the trace of 0x5bbb030

- Entry and counter construction (`0x5bbb030..0x5bbb082`, up
  to the gate): the three record rows are loaded, the counter
  word is taken into `rax`, the +1/+2/+3 variant rows are
  built with `lea`/`vpinsrd`/`shr 0x20` groups, the initial
  rows are saved on the `0x68`-byte frame and in the red zone
  for the feed-forward adds, and `test esi,esi` gates the
  zero-round path. The body's only external references are
  the four `.rodata` constants, read through the section
  table; there are no callees.
- Round loop (`0x5bbb100..0x5bbb4ad`, 189 instructions): two
  double rounds per iteration — column quarter rounds then
  diagonal quarter rounds, the diagonalisation done with
  `vpshufd` `0x39`/`0x4e`/`0x93` lane rotations. The census
  (in `records.json`, `trace.round_loop`) equals the F2
  loop's census on every count; the producer re-derives both
  censuses from the binary and requires them to be equal.
- Post-loop and zero-round paths: both join the epilogue at
  `0x5bbb55b` — the loop path via the `jmp` at `0x5bbb501`
  after the four sigma adds, the zero-round path by falling
  through from `0x5bbb503` with the doubled sigma loaded.
- Epilogue (`0x5bbb55b..0x5bbb629`): 12 `vpaddd` feed-forward
  adds, the counter write-back, 16 output stores (15
  `vmovdqu` and one `vmovups` at `+0x80`), `vzeroupper`,
  `add rsp,0x68`, `ret`.

## Stage 3 — the dispatcher and the transfer census

The producer re-derives the dispatcher's structure from its
disassembly: the feature-slot load, the two `0x4000` test
sites, all four exits in order (sign → `0x5bbb630`,
`0x4000` → `0x5bbb030`, `0x400` → `0x5bb9a60`, bit 9 →
`0x5bba120`), and the `0x4000` exit block's unwind shape.
The transfer census scans every E8/E9 byte hit in `.text`
whose relative target is the traced body and validates each
hit against the disassembly of its containing FDE (a hit
must be an instruction boundary transferring to the target).
The validated result is exactly one jump — the `0x4000` exit
jump `0x5bbafc5` — and no call.

## Explicit boundary and next question

What is **not** established: the operations of the
dispatcher's two remaining untested exits — the `0x400` exit
body at `0x5bb9a60` (FDE `0x5bb9a60..0x5bba11a`, 1,722 bytes)
and the sign-bit exit body at `0x5bbb630` (FDE
`0x5bbb630..0x5bbb994`, 868 bytes), whose addresses and FDE
spans are pinned here and in PR #2749 but whose operations
are not traced; which indirect slot or table names the
dispatcher (it has no direct caller, per PR #2749's census);
what round-count values (`esi`) any caller passes, and
therefore which ChaCha variant (8/12/20) any given invocation
computes; who consumes the 256 output bytes downstream; and
any runtime values.

Next question: trace the dispatcher's sign-bit exit body at
`0x5bbb630..0x5bbb994` (868 bytes) — the first feature exit in
test order — and name its operation: whether it is a scalar
(or otherwise reduced) form of the same ChaCha block
function, and how its counter/output contract compares to
the SSSE3 and AVX forms now pinned.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/dispatcher_4000_exit_static.py --output research/work-items/RE-002-node115-dispatcher-4000-exit
python3 -B -m unittest discover -s tests -p test_dispatcher_4000_exit_static.py -v
(cd research/work-items/RE-002-node115-dispatcher-4000-exit && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x5bbb030` (the
re-derived body hash no longer matches its pin), one byte of
the sigma constant at `0x4519c0` (the traced constants no
longer name the operation), one byte inside the F2 comparison
body `0x5bba120` (its hash pin no longer matches), and the low
byte of the `0x4000` exit jump's rel32 at `0x5bbafc5` (the
dispatcher exit pins no longer match). These are checks of
the named obligations — the body pin, the constant identity,
the comparison pin and the selection pins — not target
execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
