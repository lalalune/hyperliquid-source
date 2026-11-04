# RE-001-node115-lu-rem: the node #115 lu remainder helper

- Component ID: RE-001-node115-lu-rem
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation (disassembly-backed); the insert helper's
  internals, the second caller's purpose, and the `.bss` flag meanings
  are unresolved, stated as such
- Scope included and excluded: included — FDE `0x6369fe0..0x636a136`
  in full (entry gate, slot selection, insert call, pool accounting)
  plus the two caller sites by address. Excluded — the insert helper
  `0x63ac0d0` internals, the fresh helper `0x636a140`, the
  contention helper `0x63bf680`, the `.bss` table populator.

## Reproduce

Working directory: the packet worktree. Tools: `objdump` (binutils),
`python3` (stdlib only), `sha256sum`. No node execution at any point.

- `objdump --dwarf=frames artifacts/node/115/hl-node` shows
  `FDE pc=0000000006369fe0..000000000636a136` (342B).
- `objdump -d --start-address=0x6369fe0 --stop-address=0x636a136
  artifacts/node/115/hl-node` gives the full FDE disassembly; the
  five exhibits are contiguous slices of it (see records.json).
- `python3 tools/node115_lu_rem.py` (exit 0) re-checks binary SHA/size,
  exhibit bytes, strict mnemonic counts, key bytes, key calls, census,
  FDE bounds, and MANIFEST 15/15.
- `python3 tests/test_node115_lu_rem.py` (9/9) repeats the checks as
  unit tests including a tamper control.

## Evidence

Coordinate system: VA as shown by objdump; `.text` file offset =
VA − 0x1000; `.rela.dyn` addends for GOT (file-content scan would miss
zero-filled RELATIVE slots).

- Entry: prologue saves r13 = rdx, r12 = rcx, rbp = rdi (pool),
  rbx = r8; `mov 0x10(%rsi),%rax` at `0x6369ff6`; `je 0x636a03a`
  skips insertion when the remainder word is zero.
- Small slot: `lea 0x67277c0,%r11`; `(r + 8) >> 3` table index;
  slot = `pool + 0xa8 + (table_byte - 1) * 16` (`rm_small`).
- Large slot: `movabs $0x7000000000000000,%rcx` threshold at
  `0x636a0d0`; `bsr` on `2*r + 1` with clamp/mask/shift (`rm_large`);
  huge case `mov $0xf18,%edi` at `0x636a12c` (last slot).
- Insert: `call 0x63ac0d0` at `0x636a035` with rdi = slot, rsi = node
  (`rm_call`); no test of its return follows.
- Accounting: `add %rbx,0xf28(%rbp)`; `add %r12,%rbx` then
  `sub %r13,%r12`; 4K page-ceil difference into `pool + 0xf30`;
  flag-gated 2M page-count difference into `pool + 0xf40` (`rm_acct`,
  flags `0x6711b34`, `0x6712374`, `pool + 0x90`).
- Allocator call site `0x636a9d0` (in #216's al_found block):
  rdi = pool, rsi = block, rdx = aligned − old `[block+0x8]`
  (`sub %rdi,%rdx` at `0x636a9b7`), rcx = aligned, r8 = rounded size;
  `[block+0x10]` is written immediately before the call
  (`mov %r12,0x10(%rax)` at `0x636a9cc`).
- Second caller `0x636b2b3` (FDE `0x636b0b0..0x636b300`):
  rdi = pool, rsi = obj+0x10, rdx = [rsp+0x18], rcx = pool,
  r8 = 0xf80; purpose not decoded.
- Census: whole-`.text` E8 scan with rel32 filter gives exactly
  `0x636a9d0`, `0x636b2b3`; E9/LEA scans empty; `.rela.dyn`
  (60,723 entries) has no addend equal to `0x6369fe0`.

## Implementation and comparison

Not yet implemented/measured: this packet is evidence only; no Rust
reconstruction is included. The verifier and unit tests check the
evidence bytes against the target binary, not an implementation.

## Results and limitations

- 5 excerpts, 216 bytes, 51 strict mnemonics, all byte-exact against
  the target binary; census 2 E8 / 0 E9 / 0 LEA / 0 GOT.
- `make verify`, `make catalogue-check` pass; `make test` shows only
  the pre-existing catalogue Errno 18 failure (see README).
- Unknown: insert-helper collision/drop behaviour, second-caller
  purpose, `.bss` table populator, `.bss` flag and `pool + 0x90`
  meanings. Next question: decode the `0x63ac0d0` slot-insert helper
  end to end.
