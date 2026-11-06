# RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall: how does the twelfth 1-raw bin_table_init caller resolve four second-level pointers, and when does it report success?

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall
- Target release and full SHA-256: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation
- Scope included and excluded: the FDE `0x63af460..0x63afba4` only (1860 bytes, 369 strict mnemonic lines). Included: the null-context bin_table_init site, the four walks and their second-level pointer stores, the four 8-slot move-to-front scans, the four lu-miss sites, the rep stos stack zeroing, the canary epilogue and the `eax` return convention. Excluded (cited, not claimed): the bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss handler `0x63d9700..0x63d987b` (#215), the prev/next FDEs, the caller-side meaning of entry `rsi`/`r8d`/`r9d`, and the meaning of the four resolved pointers beyond the store sites.

## Reproduce

Working directory: a worktree of upstream main `05bc2de303c05525b71e7e257426e741bc66a390`. Static analysis only; the binary is never executed.

- FDE bounds: own `.eh_frame` parse (135,313 FDEs; CIE pointer relative to the CIE_id field, rec+4; fixed 4-byte range fields, not ULEB; FDE list sorted before bisect). Prev FDE `0x63aefe0..0x63af45f`, gap 1 byte `0xcc`; next FDE `0x63afbb0..0x63afc54`, padding 12 bytes all `0xcc`.
- Disassembly: `objdump -d --start-address=0x63af460 --stop-address=0x63afba4 artifacts/node/115/hl-node` (exhibit `bintableinit_caller_4walk_resolveall_1site.objdump.txt`).
- Bytes: raw binary slice `0x63af460..0x63afba4` (exhibit `bintableinit_caller_4walk_resolveall_1site.hex`, raw bytes, not hex text).
- Verifier: `python3 tools/node115_lu_bintableinit_caller_4walk_resolveall_1site.py` (exit 0, 179 checks, 0 failures).
- Tests: `python3 tests/test_node115_lu_bintableinit_caller_4walk_resolveall_1site.py` (exit 0, 12 checks, 0 failures; tamper controls run first).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md` on a pristine checkout. Full `make test` not run (584 files; declared in README.md).

## Evidence

Addresses are virtual addresses (VA). `.text` file offset = VA - 0x1000. Strict count = mnemonic lines matching `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (lowercase-start mnemonic).

- Window: `0x63af460..0x63afba4`, 1860 bytes, 369 strict lines, 6 calls, 1 ret at `0x63af65f`, 0 bsr, 0 lock add/sub, 61 jumps, all inside the window, no tail-jump exit.
- Frame: `endbr64` at `0x63af460`; pushes r15/r14/r13/r12/rbp/rbx; `sub $0x228,%rsp` at `0x63af47a`; canary at `0x218(%rsp)` (stored at `0x63af494`, checked against `%fs:0x28` at `0x63af63f`, mismatch jumps to `__stack_chk_fail` at `0x63afb9f` via `jne` at `0x63af648`).
- Entry: `rdi` = context (kept in `r13`), `rsi` = live input (kept in `r14`, never overwritten, passed to all four lu-miss calls), `rdx` = struct pointer (kept in `rbx`), `rcx` (kept in `r15`; `0x8(%rcx)` is the walk-1 key), `r8` (saved to `0x20(%rsp)`; `page(r8)` feeds the walk-2 derived key), `r9` (kept in `r12`; `0x8(%r12)` is the walk-3 key, `0x10(%r12)`/`0x8(%r12)` feed the walk-4 derived key).
- Null-context gate: `test %rdi,%rdi` at `0x63af49e`, `je 0x63af6b8` at `0x63af4a1` — the bin_table_init site is entered only when the context is null.
- Bin_table_init site: `0x63af6c8` (block `0x63af6b8`): `lea 0x90(%rsp),%rbp`, `mov %rbp,%rdi`; `r8` saved to `0x8(%rsp)` before the call, restored at `0x63af6cd`; `rsi` lives in callee-saved `r14` across the call; rejoin `jmp 0x63af4a7`; preceding instruction `nopw` at `0x63af667`.
- Table base in `rbp`: `lea 0x1b0(%rdi),%rbp` at `0x63af479` on the normal path; on the null-context path the bti block overwrites `rbp` with `lea 0x90(%rsp)`, so the four walks and four scans run against the stack-temp table. The bti table temp `0x90(%rsp)` is referenced nowhere else in this FDE except the bti `lea` itself.
- Stack scratch: `rep stos` zeroes 128 bytes at `0x10(%rsp)` (16 qwords: `lea 0x10(%rsp),%rdi` at `0x63af4a9`, `mov $0x10,%ecx` at `0x63af4ae`); entry `r8` saved at `0x20(%rsp)` at `0x63af4ba`, walk-1 key (`0x8(%rcx)`) saved at `0x18(%rsp)` at `0x63af4bf`; `movq $0,0x60(%rsp)` at `0x63af4c4` (inside the already-zeroed region).
- Walk 1: key = `0x18(%rsp)` (`mov 0x18(%rsp),%r11` at `0x63af4cd`); top index `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`, page `key & 0xfffffffffffff000`, top-level compare `cmp %rcx,%rax` at `0x63af4f6`; mismatch falls to scan A at `0x63af6e0`; second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`; second-level pointer stored at `mov %rax,(%rbx)` at `0x63af511` BEFORE the null test (`test %rax,%rax` at `0x63af514`, `je 0x63af573` at `0x63af517` skips walk 2 when null).
- Walk 2: derived key `page(0x20(%rsp)) + page(0x18(%rsp)) - 0x1000` (`lea -0x1000(%r11,%r15,1),%rdi` at `0x63af531`); top-level compare `cmp %rsi,%rcx` at `0x63af555`; mismatch falls to scan B at `0x63af728`; second-level pointer stored at `mov %rax,0x8(%rbx)` at `0x63af56f`. No null test after walk 2 — walk 3 always runs.
- Walk 3: key = `0x8(%r12)` (`mov 0x8(%r12),%rax` at `0x63af573`); top-level compare `cmp %rcx,%r11` at `0x63af59b`; mismatch falls to scan C at `0x63af670`; second-level pointer stored at `mov %rax,0x10(%rbx)` at `0x63af5b5` before the null test (`test %rax,%rax` at `0x63af5b9`, `je 0x63af61b` at `0x63af5bc` skips walk 4 when null).
- Walk 4: derived key `page(0x10(%r12)) + page(0x8(%r12)) - 0x1000` (`lea -0x1000(%rdx,%r12,1),%rcx` at `0x63af5d6`); top-level compare `cmp %r15,%r11` at `0x63af5fa`; mismatch falls to scan D at `0x63af770`; second-level pointer stored at `mov %rax,0x18(%rbx)` at `0x63af617`.
- Scan A (8 slots, table+`0x100` in `rbp`, key in `rax`): compares at `0x63af6e0`, `0x63af81e`, `0x63af944`, `0x63af957`, `0x63af96a`, `0x63af97d`, `0x63af990`, `0x63af99d` (slot 7 compares memory directly, `cmp 0x170(%rbp),%rax`). All normal-operand; 0 reversed-operand compares. Slot-0 inline block `0x63af6ed..0x63af71c`, shared move-to-front block at `0x63af82b` (`r8d` = slot index, `r9d` = index-1, shift `*16`).
- Scan B (8 slots, table+`0x100` in `rbp`, key in `rcx`): compares at `0x63af728`, `0x63af8e2`, `0x63afb0a`, `0x63afb1d`, `0x63afb30`, `0x63afb43` (reversed, `cmp %rcx,0x150(%rbp)`), `0x63afb56` (reversed, `cmp %rcx,0x160(%rbp)`), `0x63afb63` (slot 7 compares memory directly, `cmp 0x170(%rbp),%rcx`). Two reversed-operand compares (slots 5–6). Slot-0 inline block `0x63af735..0x63af763`, shared move-to-front block at `0x63af8ef`.
- Scan C (8 slots, table+`0x100` in `rbp`, key in `r11`): compares at `0x63af670`, `0x63af7b6`, `0x63af9dd`, `0x63af9f0` (reversed, `cmp %r11,0x130(%rbp)`), `0x63afa03`, `0x63afa16`, `0x63afa29` (reversed, `cmp %r11,0x160(%rbp)`), `0x63afa36` (slot 7 compares memory directly, `cmp 0x170(%rbp),%r11`). Two reversed-operand compares (slots 3, 6). Slot-0 inline block `0x63af67d..0x63af6ac`, shared move-to-front block at `0x63af7c3`.
- Scan D (8 slots, table+`0x100` in `rbp`, key in `r11`): compares at `0x63af770`, `0x63af880`, `0x63afa75`, `0x63afa88`, `0x63afa9b`, `0x63afaae`, `0x63afac1`, `0x63aface` (slot 7 compares memory directly, `cmp 0x170(%rbp),%r11`). All normal-operand; 0 reversed-operand compares. Slot-0 inline block `0x63af77d..0x63af7ab`, shared move-to-front block at `0x63af88d` (`r8d` = slot index, `r13d` = index-1).
- Lu-miss A: `0x63af9cd` (block `0x63af9b8`): `rcx` = `page(key1)` in `r15`, `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`; return value in `rax` stored to `0x0(%rbx)`; rejoin `jmp 0x63af511`.
- Lu-miss B: `0x63afb95` (block `0x63afb80`): `rcx` = derived key 2 in `rdi`, `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`; return value in `rax` stored to `0x8(%rbx)`; rejoin `jmp 0x63af56f`.
- Lu-miss C: `0x63afa65` (block `0x63afa50`): `rcx` = `page(key3)` in `rdx`, `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`; return value in `rax` stored to `0x10(%rbx)`; rejoin `jmp 0x63af5b5`.
- Lu-miss D: `0x63afafa` (block `0x63afae8`): `rcx` = derived key 4, carried in `rcx` from the `lea` at `0x63af5d6` (no instruction in the lu-miss block or on the scan-D miss path writes `rcx`), `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`; return value in `rax` stored to `0x18(%rbx)`; rejoin `jmp 0x63af617`.
- Calls: `0x63af6c8` -> `0x63d9880` (bin_table_init), `0x63af9cd` -> `0x63d9700` (lu-miss handler), `0x63afa65` -> `0x63d9700` (lu-miss handler), `0x63afafa` -> `0x63d9700` (lu-miss handler), `0x63afb95` -> `0x63d9700` (lu-miss handler), `0x63afb9f` -> `0x63f0d70` (`__stack_chk_fail`).
- Return value: `eax` = 1 if any of the four resolved slots is null (`mov $0x1,%eax` at `0x63af660`, reached by `je` from the first three `cmpq $0x0` tests; `sete %al` at `0x63af634` for the fourth slot). If all four are non-null, `eax` is 0 on the direct and scan paths (the last `%eax` write is a top-index `and $0xf0,%eax`, `< 0x100`). EXCEPTION: on the lu-miss-D path `rax` still holds the handler's returned second-level pointer, so the upper bytes of `eax` are pointer bits and only the low byte is the flag. Full `%eax` write list: `0x63af49c`, `0x63af4a7`, `0x63af54a`, `0x63af582`, `0x63af5ef`, `0x63af660`, `0x63af6a4`, `0x63af714`.
- No `shl/sar $0x10` + mask transform, no node-resolution tables (`0x65096c0`/`0x6511780`), no size tables (`0x6727a00`/`0x67277c0`) anywhere in this FDE.
- Census: `.rela.dyn` 60,723 total / 59,534 RELATIVE (readelf -W), `.rela.plt` 278; raw `0xe8` census 108 total (tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17), this FDE raw 1.
- Disjointness: range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records, 0 skipped; window overlaps no prior range (verifier run figure in README.md).

## Implementation and comparison

Not yet implemented. This packet is observation only; no Rust reconstruction is claimed.

## Results and limitations

- Verifier: exit 0, 179 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md`.
- Disjointness: verifier scanned 64,752 priors, 0 skipped, NONE (deduplicated figure 63,934 after removing 818 within-file duplicate ranges).
- Unknowns: caller-side meaning of entry `rsi`/`r8d`/`r9d`; meaning of the four resolved pointers beyond the store sites; the caller-side origin of the walk-3/walk-4 keys in `r9`'s struct.
- Correction carried forward: the #298–#305 surveys listed packet #307's window with 2 lu-miss sites; packet #306 proved by objdump census it has 1 (`0x63aefcd`). This packet's own census re-verifies the corrected figure.
- Next question: packet #310 decodes `0x63afc60..0x63b0324` (1732 bytes, 1 bin_table_init site `0x63afe1e`, 4 lu-miss sites, 1 ret, 0 bsr); fall-through `0x63bc490..0x63bc728`, `0x63bc730..0x63bcb12`, `0x63c2f00..0x63c3328`.
