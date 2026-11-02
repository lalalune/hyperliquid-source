# foundation: inverted-mask descriptor helper (node #94, 0x36f5790)

Baseline: node #94 only (91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
Worktree HEAD: 2993e46 (same as the main clone; no upstream sync).
Static analysis only; no binary execution, no network, no chain actions.

## Summary

An 82-byte zero-call window at `0x36f5790` (node #94) that derives an
inverted most-significant-bit mask from the first 16 bytes of its input
with `pmovmskb` + `not`, builds a stack descriptor carrying that mask,
calls one shared callee with `(obj, &descriptor)`, and returns `obj`.
One mask derivation, one call, no branch, no loop, no second callee.
The callee's behavior is excluded from the rule; only its identity and
extent are locked.

## Rule

Let `obj = rdi` (returned unchanged) and `src = rsi`, where `src`
points to a struct with `data = [src]`, `len = [src+8]`, and an extra
field `[src+0x18]`. Then:

1. `mask = (~pmovmskb(data[0:16])) & 0xffff` — the bitwise inversion of
   the 16 most-significant-bit flags of the first 16 input bytes,
   truncated to 16 bits (stored via `dx`).
2. Build a stack descriptor at `rsp+8`:
   - `+0x00`: `data`
   - `+0x08`: `data+16`
   - `+0x10`: `data+len+1`
   - `+0x18`: `mask` (2 bytes)
   - `+0x20`: `[src+0x18]` (copied unchanged)
3. Call `0x3bb2290` with `rdi = obj`, `rsi = &descriptor`.
4. Return `obj`.

The mask is derived before the call and feeds it through the
descriptor. That ordering is disclosed, not hidden: the derivation is
a genuine computation (a new 16-bit value from the input bytes), not
argument shuffling — every shuffle-only candidate found in this hunt
was rejected below.

## Window

- Start `0x36f5790`, end (exclusive) `0x36f57e2`, 82 bytes
- FDE section offset `0x0016a01c`, CIE `0x00000000`
- Previous FDE `0x36f5710..0x36f5782` (offset `0x00169ffc`, CIE
  `0x00000000`); the 14 bytes between its end and this window start are
  int3 padding of the previous function, not part of this window
- Padding: 14 bytes int3 to the next FDE at `0x36f57f0`
- Body SHA-256
  `085f13696c9fb7f884c570851773baa5ffe35e0e5a0d19f245b8bc33a1dd381e`
- The window does not start with `endbr64`; its first instruction is
  `push rbx`. The FDE range is the authority for the window start.
- Instruction walk: `push rbx; sub rsp, 0x30; mov rbx, rdi;
  mov rax, [rsi]; mov rcx, [rsi+8]; lea rcx, [rax+rcx+1];
  movdqa xmm0, [rax]; pmovmskb edx, xmm0; not edx;
  mov [rsp+0x20], dx; mov [rsp+8], rax; add rax, 0x10;
  mov [rsp+0x10], rax; mov [rsp+0x18], rcx; mov rax, [rsi+0x18];
  mov [rsp+0x28], rax; lea rsi, [rsp+8]; call 0x3bb2290;
  mov rax, rbx; add rsp, 0x30; pop rbx; ret`
- The window has no tail jump: control returns normally with `obj`.
- The mask: `pmovmskb` collects bit 7 of each of the 16 bytes into a
  16-bit value; `not` inverts all 32 bits of `edx`, and storing `dx`
  keeps exactly the low 16 inverted bits. The mask is therefore the
  bitwise complement of the MSB pattern, independent of the remaining
  input bytes.
- Rule edges: `pmovmskb` `0x0000` -> mask `0xffff`; `0xffff` ->
  `0x0000`; `0x0001` (first byte MSB only) -> `0xfffe`; `0x5555`
  (alternating) -> `0xaaaa`; `0x8000` (last byte MSB only) ->
  `0x7fff`. Edges are model checks on the recorded arithmetic, not
  executions of the target binary.

## Callee

- `0x3bb2290`, 849 bytes, FDE start, offset `0x004ff5e0`, CIE
  `0x002dc714` (nonzero CIE, read from the `cie=` field), 15 bytes
  int3 padding to the next FDE at `0x3bb25f0` (offset `0x004ff634`,
  CIE `0x002dc714`), body SHA-256
  `0dcbcece09c6da1da96e3db0b2fce6ab4d8bb197bb0df7d95f41022fe612013b`
- Called from 3 direct sites in `.text`: this window (`0x36f57d4`)
  and two sites inside larger functions (`0x36ff858`, `0x3704aea`).
  Neither of the other two sites lies inside a single-call census
  window (containment checked against all 31,898 census windows), so
  no other small single-call window calls this callee — but the
  sharing is disclosed, not hidden.
- Because the callee is 849 bytes, its body is locked by length,
  SHA-256 and padding rather than per instruction; that locks its
  identity and extent, which is all the rule uses.

## Incoming calls

A byte-pattern scan of `.text` for direct `e8` calls to `0x36f5790`
finds exactly zero sites, so this packet has no caller file (five
files in the work-item directory). Register-indirect references, other
pointer paths, prefixes, and data sections are not a complete xref
census.

## Twins and uniqueness

Raw FDE bytes, position-wise equal bytes, no normalization. Two claimed
cohorts: A = claimed windows present in the 20–150B single-call census;
B = every claimed window from every `evidence.json` in prior worktrees
and the main tree (the comprehensive set, including #150–#154).

- Against claimed windows: maximum similarity 0.084 max-length
  (cohorts A and B agree, at `0x528e900`), well below the 0.60 cutoff.
- Against the full corpus of 31,898 single-call FDE windows: best
  non-self 0.175 max-length (at `0x32e2780`) and 0.250 min-length with
  the 20-byte floor (at `0x37f3ee0`).
- The mnemonic skeleton is a singleton among 31,898 single-call FDE
  windows of 20-150 bytes, and this window is the only single-call
  census window calling `0x3bb2290`.
- Measure validation: the same procedure reproduces #154's
  claimed-best 0.122 max / 0.125 min and corpus-best 0.159 / 0.304,
  and #153's claimed-best 0.133 max / 0.143 min and corpus-best
  0.167 / 0.200 exactly.

## Rejected candidates

- `0x4f9af60` (100B): allocation + zero-initialization helper; at the
  size boundary and a struct-init shape.
- `0x5432d40` / `0x5433140` (44B): shuffle-only tail-jump twins;
  call result forwarded unchanged, no own computation.
- `0x541b780` (50B) / `0x541c730` (70B): `xchg` + field-zeroing
  family pair (same callee `0x5334a90`, same post-call zeroing shape
  as rejected `0x5459700`/`0x5459740`/`0x5459780`).
- `0x53eab70` (98B): static-init / `__cxa_atexit` registration stub;
  global zeroing only, no derived value.
- `0x4f94730` (50B) / `0x543ff70` (77B): `operator new` allocation +
  constant field init (struct-init family).
- `0x282fc40` / `0x282fc80` / `0x282fe10` / `0x282fe50` /
  `0x282ff10` (49B each): identical template family; plain-equality
  zero-test (`cmpq $0, 0x10(rdi); sete`) whose boolean is returned,
  not fed to the call.
- `0x525baa0` (48B): call result discarded (`xor eax, eax` right
  after the call), then field zero-init.
- `0x5285a90` (60B) / `0x4fa8570` (45B): string PLT call
  (`_M_replace` / `_M_assign`) followed by the same zero-init tail;
  `0x4fa8570` is a near sibling of rejected `0x4fa8540`.
- `0x565a560` (94B) / `0x565a5c0` (97B): `mulx` pair whose product is
  discarded by the intervening call (dead computation, not a rule).
- `0x539b360` (41B) / `0x5447780` (48B) / `0x52f2b10` (61B):
  `operator new` allocation + init.
- `0x5007fe0` (72B) / `0x53cf0d0` (75B): `__cxa_atexit` static-init
  stubs, zeroing only.
- The remaining zero-incoming sweep rows are mov-only forwarding
  wrappers with no strong operation; no derived value.
- `0x521b5a0` (24B): genuine bit-extract (`shr 4; and 1`) but too thin
  for a standalone packet; remains unclaimed behind this window.

## Limits

- The callee's behavior is excluded; only its identity and extent are
  locked. The rule therefore says what the window computes and which
  function it calls with the descriptor, not what that function does.
- The mask derivation happens before the call and is shared through
  the descriptor; it is a real derivation (proved above), not a
  shuffle.
- Descriptor bytes at `+0x1a..+0x1f` are not written by this window
  (only the 2-byte mask is stored at `+0x18`); the callee is assumed
  to read only the defined fields, and the gap is disclosed.
- The window has no `ret`-less exit: it returns normally with `obj`.
- Nearest-symbol annotations carry large offsets and are not
  identifications; no symbol name is claimed.
- The caller claim covers direct `e8` calls in `.text` only.

## Verification

- `MANIFEST.sha256`: `sha256sum -c` passes
- `tools/foundation_inverted_mask.py --check`: reproduces exactly
- Unit tests: 22/22 (real evidence + 21 corruption controls, each
  mutating exactly one recorded fact)
- `make doctor`: analysis_ready true
- `make verify`, `make catalogue-check`: pass
- `make test`: base 442 + 22 new, no regressions
