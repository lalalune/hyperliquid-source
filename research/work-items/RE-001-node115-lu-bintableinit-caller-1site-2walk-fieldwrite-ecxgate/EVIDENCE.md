# RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite-ecxgate: how does the eleventh 1-raw bin_table_init caller write two composed field values, and when does it return early?

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite-ecxgate
- Target release and full SHA-256: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation
- Scope included and excluded: the FDE `0x63aefe0..0x63af45f` only (1151 bytes, 243 strict mnemonic lines). Included: the null-context bin_table_init site, the `ecx == 0xe8` early return, the two walks and their composed field writes, the second-walk gate, the two 8-slot move-to-front scans, the two lu-miss sites, the canary epilogue. Excluded (cited, not claimed): the bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss handler `0x63d9700..0x63d987b` (#215), the prev/next FDEs, the caller-side meaning of entry `rsi`/`r8d`, and the meaning of the stored composed values beyond the write sites.

## Reproduce

Working directory: a worktree of upstream main `05bc2de303c05525b71e7e257426e741bc66a390`. Static analysis only; the binary is never executed.

- FDE bounds: own `.eh_frame` parse (135,313 FDEs; CIE pointer relative to the CIE_id field, rec+4; fixed 4-byte range fields, not ULEB; FDE list sorted before bisect). Prev FDE `0x63aed40..0x63aefdb`, gap 5 bytes all `0xcc`; next FDE `0x63af460..0x63afba4`, padding 1 byte `0xcc`.
- Disassembly: `objdump -d --start-address=0x63aefe0 --stop-address=0x63af45f artifacts/node/115/hl-node` (exhibit `bintableinit_caller_2walk_fieldwrite_ecxgate_1site.objdump.txt`).
- Bytes: raw binary slice `0x63aefe0..0x63af45f` (exhibit `bintableinit_caller_2walk_fieldwrite_ecxgate_1site.hex`, raw bytes, not hex text).
- Verifier: `python3 tools/node115_lu_bintableinit_caller_2walk_fieldwrite_ecxgate_1site.py` (exit 0, 138 checks, 0 failures).
- Tests: `python3 tests/test_node115_lu_bintableinit_caller_2walk_fieldwrite_ecxgate_1site.py` (exit 0, 12 checks, 0 failures; tamper controls run first).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md` on a pristine checkout. Full `make test` not run (584 files; declared in README.md).

## Evidence

Addresses are virtual addresses (VA). `.text` file offset = VA - 0x1000. Strict count = mnemonic lines matching `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (lowercase-start mnemonic).

- Window: `0x63aefe0..0x63af45f`, 1151 bytes, 243 strict lines, 4 calls, 1 ret at `0x63af0e9`, 0 bsr, 0 lock add/sub, 35 jumps, all inside the window, no tail-jump exit.
- Frame: `endbr64` at `0x63aefe0`; pushes r15/r14/r13/r12/rbp/rbx; `sub $0x1a8,%rsp` at `0x63af004`; canary at `0x198(%rsp)` (stored at `0x63af014`, checked against `%fs:0x28` at `0x63af0c9`, mismatch jumps to `__stack_chk_fail` at `0x63af3bf` via `jne` at `0x63af0d2`).
- Entry: `rdi` = context (kept in `rbp`), `rsi` = live input (kept in `r15`, never overwritten), `rdx` = struct pointer (kept in `rbx`), `ecx` (kept in `r12d`), `r8d` (kept in `r14d`).
- Null-context gate: `test %rdi,%rdi` at `0x63af01e`, `je 0x63af190` at `0x63af021` — the bin_table_init site is entered only when the context is null; after the call the walk restarts at the `ecx` gate (`jmp 0x63af027` at `0x63af1a0`).
- `ecx` gate: `cmp $0xe8,%r12d` at `0x63af027`, `je 0x63af0c1` at `0x63af02e`. `ecx == 0xe8` returns via the shared epilogue at `0x63af0c1` and `ret` at `0x63af0e9` with no table work.
- Walk 1: `lea 0x1b0(%rdi),%rdx` (table) at `0x63aeffd`; key `0x8(%rbx)` at `0x63af034`; struct fields from `(%rbx)` at `0x63af038` (3-bit field `(x >> 0x11) & 7` in `r13d`, 1-bit field `(x >> 0x2c) & 1` in `r10d`); top index `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`, top-level compare `cmp %rdi,%rsi` at `0x63af06a`; mismatch falls to scan A at `0x63af1a8`; second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`; null second level skips the write (`test %rcx,%rcx` at `0x63af081`, `je 0x63af0bc` at `0x63af084`).
- Write 1: composed value `(struct & 0xffffffffffff) | r8b | (ecx << 0x30) | (((%rbx) >> 0x11 & 7) * 4) | (((%rbx) >> 0x2c & 1) * 2)`, stored at `mov %rax,(%rcx)` at `0x63af0b9`.
- Second-walk gate: `test %r14b,%r14b` at `0x63af0bc`, `jne 0x63af0f0` at `0x63af0bf`; inside it, `page(0x10(%rbx)) <= 0x1000` returns immediately (`cmp $0x1000,%r14` at `0x63af0fb`, `jbe 0x63af0c1` at `0x63af102`).
- Walk 2: derived key `page(0x10(%rbx)) + page(0x8(%rbx)) - 0x1000` (`lea -0x1000(%r14,%rcx,1),%rsi` at `0x63af10f`); top-level compare `cmp %r8,%rdi` at `0x63af133`; mismatch falls to scan B at `0x63af1e8`; null second level returns (`test %rdx,%rdx` at `0x63af14d`, `je 0x63af0c1` at `0x63af150`).
- Write 2: same composed value with constant `1` in place of `r8b` (`or $0x1,%rdi` at `0x63af17b`), stored at `mov %rdi,(%rdx)` at `0x63af17f`.
- Scan A (8 slots, table+`0x100` in `rdx`, key in `rsi`): compares at `0x63af1a8`, `0x63af22e`, `0x63af323`, `0x63af336`, `0x63af349`, `0x63af35c`, `0x63af36f`, `0x63af37c` (slot 7 compares memory directly, `cmp 0x170(%rdx),%rsi`). All normal-operand; 0 reversed-operand compares. Slot-0 inline block `0x63af1b1..0x63af1de`, shared move-to-front block at `0x63af23b` (`r8d` = slot index, `r9d` = index-1, shift `*16`).
- Scan B (8 slots, table+`0x100` in `rdx`, key in `rdi`): compares at `0x63af1e8`, `0x63af2ac`, `0x63af3ca`, `0x63af3dd`, `0x63af3f0`, `0x63af403`, `0x63af416`, `0x63af423` (slot 7 compares memory directly, `cmp 0x170(%rdx),%rdi`). All normal-operand; 0 reversed-operand compares. Slot-0 inline block `0x63af1f5..0x63af223`, shared move-to-front block at `0x63af2b9` (`r9d` = slot index, `ebp` = index-1).
- Bin_table_init site: `0x63af198` (block `0x63af190`): `lea 0x10(%rsp),%r13`, `mov %r13,%rdi`; no save/restore (`rsi` in callee-saved `r15`, `rdx` restored from `r13` after the call); rejoin `jmp 0x63af027`; preceding instruction `nopw` at `0x63af187`.
- Lu-miss A: `0x63af3a8` (block `0x63af390`): `r9d` = 1, `r8d` = 0, `rdi` = context in `rbp`, `rsi` = entry `rsi` in `r15`, `rdx` = scan table (saved to `(%rsp)`, restored), `r10b` saved to `0xf(%rsp)` and restored; return value in `rax` lands in `rcx`; rejoin `jmp 0x63af081`.
- Lu-miss B: `0x63af44d` (block `0x63af437`): `rcx` = derived key in `rsi`, `r9d` = 1, `r8d` = 0, `rdi` = context in `rbp`, `rsi` = entry `rsi` in `r15`, `rdx` = scan table, `r10b` saved to `(%rsp)` and restored; return value in `rax` lands in `rdx`; rejoin `jmp 0x63af14d`.
- Calls: `0x63af198` -> `0x63d9880` (bin_table_init), `0x63af3a8` -> `0x63d9700` (lu-miss handler), `0x63af3bf` -> `0x63f0d70` (`__stack_chk_fail`), `0x63af44d` -> `0x63d9700` (lu-miss handler).
- Return value: `eax` = 0 on the ret path (`xor %eax,%eax` at `0x63af01c`; the only other `%eax` writes are the two top-index `and $0xf0,%eax` at `0x63af05b`/`0x63af128`; the epilogue canary sub at `0x63af0c9` leaves `rax` 0; the move-to-front blocks do not touch `eax`).
- No `shl/sar $0x10` + mask transform, no node-resolution tables (`0x65096c0`/`0x6511780`), no size tables (`0x6727a00`/`0x67277c0`) anywhere in this FDE.
- Census: `.rela.dyn` 60,723 total / 59,534 RELATIVE (readelf -W), `.rela.plt` 278; raw `0xe8` census 108 total (tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17), this FDE raw 1.
- Disjointness: range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records, 0 skipped; window overlaps no prior range (verifier run figure in README.md).

## Implementation and comparison

Not yet implemented. This packet is observation only; no Rust reconstruction is claimed.

## Results and limitations

- Verifier: exit 0, 138 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md`.
- Disjointness: verifier scanned 63,910 priors, 0 skipped, NONE (deduplicated figure 63,102 after removing 808 within-file duplicate ranges).
- Unknowns: caller-side meaning of entry `rsi`/`r8d`; meaning of the composed stored values beyond the write sites; why `ecx == 0xe8` returns early.
- Correction carried forward: the #298–#305 surveys listed packet #307's window with 2 lu-miss sites; packet #306 proved by objdump census it has 1 (`0x63aefcd`). This packet's own census re-verifies the corrected figure.
- Next question: packet #309 decodes `0x63af460..0x63afba4` (1860 bytes, 1 bin_table_init site `0x63af6c8`, 4 lu-miss sites, 1 ret, 0 bsr); fall-through `0x63afc60..0x63b0324`, `0x63bc490..0x63bc728`, `0x63bc730..0x63bcb12`, `0x63c2f00..0x63c3328`.
