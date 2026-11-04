# RE-001: the node #115 lu miss handler — directory, evict, then insert

- Component ID: RE-001-node115-lu-miss
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (fetch-confirmed unmoved before analysis)
- Claim status: observation (disassembly-backed); unresolved items listed at the end
- Scope included and excluded: included — FDE `0x63d9700..0x63d987b` end to end, its census, its record layout, its return contract, the worker re-entry at `0x63adfed`. Excluded — allocator `0x636b370` internals, contention helper `0x63bf680` internals, detour `0x63d9880` internals, all other callers' functions beyond their arg setup.

## Reproduce

Worktree `~/workspace/hl-wt-calls215-115`, local branch
`codex/re-004-calls215-115`, from `origin/main` of
`~/workspace/hyperliquid-source` (main clone HEAD untouched at `2993e46`).
Static analysis only; the node binary was never executed.

```sh
objdump --dwarf=frames artifacts/node/115/hl-node   # FDE 0x63d9700..0x63d987b
objdump -d --start-address=0x63d9700 --stop-address=0x63d987b artifacts/node/115/hl-node
objdump -d --start-address=0x63ae220 --stop-address=0x63ae248 artifacts/node/115/hl-node  # worker call setup
readelf -r artifacts/node/115/hl-node  # 60,723 .rela.dyn entries, no 0x63d9700 addend
```

Coordinate system: `.text` file offset = VA − 0x1000, verified by
`endbr64` at `0x63d9700` and at the thunk `0x63ae260`. Tool versions:
system `objdump`/`readelf` (binutils), Python 3 stdlib only for the
verifier and tests.

## Evidence

Original addresses and validated boundaries:

- FDE `0x63d9700..0x63d987b` (379B) from `.eh_frame`; single `ret` at
  `0x63d97af`; `int3` padding after `0x63d987b`. No stack canary in this
  FDE (no `%fs:0x28` reference).
- Prologue (excerpt `mh_head`, 57B/18 strict): `endbr64`, pushes, `lea
  0x78(%rsi),%rax` (directory base), `r12 = table`, `rbp = rbx = key`,
  `rbx = (key>>30) & 0x3ffff`, `rdx = rbx*8`, `test %r9b,%r9b`.
- Fast path (excerpt `mh_fast`, 31B/8 strict): `0x63d9830`: `rax =
  record+0x78 + idx*8`, `r13 = *rax`, `test %r8b` → insert on nonzero,
  `test %r13` → NULL (`xor %eax,%eax`) on zero.
- Insert path (excerpt `mh_insert`, 92B/18 strict): `and $0xf,%ebx`,
  `memmove(table+0x110, table+0x100, 0x70)` via PLT `0x63f0a70`,
  `rcx = table + ((key>>30)&0xf)*16`, bucket word → overflow slot 0,
  masked key → bucket, directory value → bucket value, `rax = r13 +
  ((key>>9) & 0x1ffff8)`.
- Lock path (excerpt `mh_lock`, 34B/9 strict): `lea 0x48(%rsi),%rdi`,
  `pthread_mutex_trylock@plt` (`0x63f17b0`), `test %eax` → contention
  helper `0x63bf680(record+0x8)` at `0x63d984f`, `movb $0x1,0x70(%r14)`.
- Alloc path (excerpt `mh_alloc`, 32B/9 strict): `rsi = *record`,
  `ecx = 0x40`, `edx = 0x200000`, `rdi = thread`, `call 0x636b370`,
  `r13 = rax`.
- Key-byte checked, not excerpted: `ret` at `0x63d97af`; unlock calls
  `pthread_mutex_unlock@plt` (`0x63f0b70`) at `0x63d981c` and `0x63d986f`;
  `movb $0x0,0x70(%r14)` at `0x63d9813` and `0x63d9866`; post-lock
  accounting (`addq $1,0x40(%r14)`, `cmp 0x38(%r14),%r8`,
  `addq $1,0x30(%r14)`, `mov %r8,0x38(%r14)`) at `0x63d97d7..0x63d97e7`;
  NULL returns (`xor %eax,%eax`) at `0x63d9848` and `0x63d9874`;
  worker re-entry `jmp 0x63adfed` at `0x63ae248`.
- Callers/callees: 168 direct E8 callers (see Census); callees
  `memmove@plt`, `pthread_mutex_trylock@plt`, `pthread_mutex_unlock@plt`,
  `0x63bf680` (contention, characterised only), `0x636b370` (allocator,
  characterised only). No indirect calls in this FDE.
- Worker call setup (independent objdump read): at `0x63ae220`,
  `rdx = table base`, `r9d = 0`, `r8d = 0`, `rcx = key`, `rdi = thread`,
  `call 0x63d9700` at `0x63ae239`, then `jmp 0x63adfed` at `0x63ae248`.
  The worker's `rsi` (`[ref+0xe410]`) is preserved across the call.
- Census method: whole-file `E8` byte scan with rel32-target filter
  (168 candidates) + per-site disassembly + arg-setup read in a 72-byte
  window before each call. Mode split: `(1, 0)` × 159, `(0, 1)` × 8,
  `(0, 0)` × 1 (the worker). No `(1, 1)` combination observed. The
  coherence of the arg setup across all 168 sites (literal `mov
  $0x1,%r8d` / `xor %r9d,%r9d` / `xor %r8d,%r8d` / `mov $0x1,%r9d`
  immediately before the call) confirms the candidates are genuine
  instructions, not data bytes. E9 scan: 0. LEA scan (RIP-relative forms):
  0. `.rela.dyn` addends: 0 hits for `0x63d9700` over 60,723 entries.
- Analysis was complete for this FDE and its census. No bytes from
  packets #183–#214 are re-claimed.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in this
packet; the evidence is disassembly observation only, per the light-style
packet skeleton (same as packets #199–#214).

## Results and limitations

Metrics with denominators: 5 excerpts, 246 bytes, 62 strict mnemonics;
census 168 E8 / 0 E9 / 0 LEA / 0 GOT; FDE 379B; MANIFEST 15/15; unit tests
8/8; `make verify` exit 0 (29 manifests, 471 entries);
`make catalogue-check` exit 0; `make test` 77 files attempted, 1 failed —
the pre-existing `test_node115_catalogue` Errno 18 cross-device-link
error, identical on pristine checkouts, not a packet regression; this
packet's file passes 8/8.

What remains unknown, and why: allocator `0x636b370` internals (next
question); contention helper `0x63bf680` internals (shared with #210);
detour `0x63d9880` internals (open since #214); the directory's
allocation origin (the `+0x78` base is addressed, not allocated, in this
FDE); the record identity for non-worker callers; the design intent
behind the bit ranges (directory bits 30..47 vs bucket bits 26..29) and
the absent `(1, 1)` mode. No gate is requested beyond this packet's own
evidence.

Next question: decode the `0x636b370` allocator end to end — what it does
with `(thread, pool, 0x200000, 0x40)`, what block pointer it returns,
when it returns NULL, and how the `0x40` argument shapes the allocation.
