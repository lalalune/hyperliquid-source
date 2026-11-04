# RE-001-node115-lu-drain-helper: bounded question

- Component ID: RE-001-node115-lu-drain-helper
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db6`
- Claim status: observation (disassembly + byte scans); inference
  flagged where used (weight-curve reading of the table, #204's
  batch-count labels reused for entry+0xb0 / C+0x88); unresolved
  items listed at the end.
- Scope included: drain FDE `0x63697a0..0x63697d2`, accumulator
  core `0x63a9712..0x63a9742` inside FDE `0x63a96f0..0x63a974a`,
  load stub FDE `0x63bfb90..0x63bfb98`, whole-`.text` census for
  drain/accumulator/predicate/stub, `.rela.dyn` GOT scan,
  `.rodata` table at `0xb9e140`.
- Scope excluded: full decodes of the workers `0x63c19a0` /
  `0x63c1930`, the tail route body beyond its drain/accumulator
  call sites (already claimed by #207), the entry+8 waiters, and
  all `.bss` contents.

## Reproduce

Working directory: a fresh worktree of upstream main `8fd8db6`
(`~/workspace/hl-wt-calls208-115`), binary
`artifacts/node/115/hl-node` (105,896,032 bytes, SHA-256 above).
Static analysis only; the node binary was never executed.
Commands: `objdump -d --start-address=... --stop-address=...`,
`readelf --debug-dump=frames`, `readelf -SW`, `readelf -r`,
`od -An -tx1` for byte reads. Coordinate system: `.text` file
offset = VA - 0x1000, `.rodata` VA = file offset, `.got` /
`.data.rel.ro` file offset = VA - 0x2000. No execution, no side
effects.

## Evidence

Drain FDE bounds from `.eh_frame`:
`pc=0x63697a0..0x63697d2` (50B). Body, verbatim in
`drain.hex` / `drain.objdump.txt` (15 strict instrs + 1
byte-continuation line for the `nopw` padding):

- `0x63697a8 test %rsi,%rsi; 0x63697ab je 0x63697bd` — NULL
  buffer bypasses the compare.
- `0x63697b0 call 0x63bfb90` (bytes `e8 db 63 05 00`;
  target = 0x63697b0 + 5 + 0x563db = 0x63bfb90); stub body
  (`stub.hex`) is `endbr64; mov (%rdi),%rax; ret`, so rax =
  *(buffer).
- `0x63697b5 cmp $0x5f5e0ff,%rax` (99,999,999);
  `0x63697bb jbe 0x63697d0` (unsigned) → silent return.
- `0x63697bd lea 0x8(%rbx),%rdi; 0x63697c2 jmp 0x63f1800`
  (bytes `e9 39 80 08 00`; target = 0x63697c2 + 5 + 0x88039 =
  0x63f1800 = `pthread_cond_signal@plt`, JUMP_SLOT reloc at
  `0x64ee850` confirmed via `readelf -r`).

Census (whole `.text`, 0x4fd7700 bytes, E8/E9 rel32 byte scan
with per-site disassembly check; `.rela.dyn` RELATIVE scan):

- Drain: E8 `0x635f632` (tail threshold path: rsi = stackbuf
  at `0x635f62c`, rdi = entry at `0x635f62f`), `0x635f645`
  (tail predicate path: `xor %esi,%esi` at `0x635f640`, rdi =
  entry at `0x635f642`); 0 E9, 0 LEA, 0 GOT.
- Accumulator: E8 `0x635f681` only (tail arg4 branch:
  rdi = C at `0x635f67e`, rsi = stackbuf at `0x635f67b`,
  rdx = arg4 at `0x635f678`); 0/0/0.
- Predicate: E8 `0x635f526` only; 0/0/0.
- Stub: 60 E8 sites (generic helper); 0/0/0.

Accumulator core (`accum.hex`, 48B, 12 strict), inside FDE
`0x63a96f0..0x63a974a` (90B, `.eh_frame`):

- Prologue (address-cited, not exhibited): `sub $-0x80,%rdi`
  at `0x63a96f6`, then `call 0x63bfb90` at `0x63a9702` gives
  D = *(C-0x80); `call 0x63bfb90` at `0x63a970d` gives
  N = *(stackbuf).
- `0x63a9712 xor %edx,%edx; 0x63a9714 div %rbp` → q = N/D
  unsigned; no divisor-zero test precedes the `div`.
- `0x63a9717 cmp $0xc7,%rax; 0x63a971d ja 0x63a9742` →
  q > 199 returns arg4 unchanged (rbx, set at entry).
- `0x63a9724 lea -0x580b5eb(%rip),%rcx` → table base
  `0xb9e140` (0x63a972b - 0x580b5eb); `0x63a972b sub %rax,%rsi`
  with rsi preset to 199 → index 199-q; `0x63a972e mov
  $0x1000000,%eax`; `0x63a9733 sub (%rcx,%rsi,8),%rax`;
  `0x63a9737 imul %rbx,%rax`; `0x63a973b shr $0x18,%rax`
  → return arg4 * (2^24 - table[199-q]) >> 24.
- Table check (`.rodata`, VA = file offset): 200 qwords at
  `0xb9e140`, strictly monotone nondecreasing, table[0] = 20,
  table[199] = 16777216 = 2^24. Factor (2^24 - table[199-q]) /
  2^24 is 0 at q = 0, ~0.49 near q = 100, ~1 at q = 199.

Tail-route stackbuf identity (read-only context from #207's
call sites, not re-exhibited): stackbuf[0] = *(entry+0xb0),
then `0x63bfc00` sign-compares it against *(C+0x88), and only
on a positive result `0x63bfc40` subtracts *(C+0x88), leaving
stackbuf[0] = *(entry+0xb0) - *(C+0x88) > 0. The accumulator
reads that difference as N; the threshold-path drain reads
the same value as *(buffer).

Disjointness: claimed ranges (drain `0x63697a0..0x63697d2`,
accum `0x63a9712..0x63a9742`, stub `0x63bfb90..0x63bfb98`)
do not overlap any #202–#207 exhibit (fast-path, slow-path,
flush, push, fallback-inner, tail-route ranges; checked in
the verifier). The accum excerpt starts mid-FDE by design;
only its 48 bytes are claimed.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed
for the drain or accumulator in this packet; the packet is
evidence only (README + records + verifier + tests).

## Results and limitations

- Drain decoded end to end: NULL → signal; *(buffer) >
  99,999,999 → signal; else silent. Entry+8 identified as a
  pthread condvar by PLT target + reloc.
- +0xb8 counts weighted arg4 units with weight(q) as above;
  threshold 0x400 with reset-to-0 on drain is the tail
  route's behavior (#207), re-confirmed at the call sites.
- Unknown: *(C-0x80) enclosing struct; arg4 units; N/D
  semantic labels; drain-threshold unit; entry+8 waiters;
  all `.bss` contents; table provenance.
- Next question: decode workers `0x63c19a0` / `0x63c1930`
  (modes 0, 1, 2 - bss byte; the seg+0x29b0 reference).
