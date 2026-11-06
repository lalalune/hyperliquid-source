# RE-001-node115-lu-bintableinit-caller-1site-pageinstall-earlyret: how does the tenth 1-raw bin_table_init caller install a page range, and when does it return early?

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-pageinstall-earlyret
- Target release and full SHA-256: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation
- Scope included and excluded: the FDE `0x63aed40..0x63aefdb` only (667 bytes, 149 strict mnemonic lines). Included: the small-range early return, the page-range install loop, the single 8-slot move-to-front scan, the bin_table_init site, the lu-miss site, the canary epilogue. Excluded (cited, not claimed): the bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss handler `0x63d9700..0x63d987b` (#215), the prev/next FDEs, the caller-side meaning of entry `rsi`, and the meaning of the stored constant `0xe8000000000000` beyond the write site.

## Reproduce

Working directory: a worktree of upstream main `05bc2de303c05525b71e7e257426e741bc66a390`. Static analysis only; the binary is never executed.

- FDE bounds: own `.eh_frame` parse (135,313 FDEs; CIE pointer relative to the CIE_id field, rec+4; fixed 4-byte range fields, not ULEB; FDE list sorted before bisect). Prev FDE `0x63ae980..0x63aed39`, gap 7 bytes all `0xcc`; next FDE `0x63aefe0..0x63af45f`, padding 5 bytes all `0xcc`.
- Disassembly: `objdump -d --start-address=0x63aed40 --stop-address=0x63aefdb artifacts/node/115/hl-node` (exhibit `bintableinit_caller_pageinstall_earlyret_1site.objdump.txt`).
- Bytes: raw binary slice `0x63aed40..0x63aefdb` (exhibit `bintableinit_caller_pageinstall_earlyret_1site.hex`, raw bytes, not hex text).
- Verifier: `python3 tools/node115_lu_bintableinit_caller_pageinstall_earlyret_1site.py` (exit 0, 110 checks, 0 failures).
- Tests: `python3 tests/test_node115_lu_bintableinit_caller_pageinstall_earlyret_1site.py` (exit 0, 12 checks, 0 failures; tamper controls run first).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md` on a pristine checkout. Full `make test` not run (584 files; declared in README.md).

## Evidence

Addresses are virtual addresses (VA). `.text` file offset = VA - 0x1000. Strict count = mnemonic lines matching `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (lowercase-start mnemonic).

- Window: `0x63aed40..0x63aefdb`, 667 bytes, 149 strict lines, 3 calls, 1 ret at `0x63aedb5`, 0 bsr, 0 lock add/sub, 24 jumps, all inside the window, no tail-jump exit.
- Frame: `endbr64` at `0x63aed40`; pushes r15/r14/r13/r12/rbp/rbx; `sub $0x1a8,%rsp` at `0x63aed55`; canary at `0x198(%rsp)` (stored at `0x63aed68`, checked against `%fs:0x28` at `0x63aed95`, mismatch jumps to `__stack_chk_fail` at `0x63aef60` via `jne` at `0x63aed9e`).
- Entry: `rdi` = context (kept in `r12`), `rsi` = live input, `rdx` = struct pointer. `ecx`/`r8d` unused.
- Early return: `mov 0x10(%rdx),%rax` at `0x63aed7b`, `and $0xfffffffffffff000,%rax` at `0x63aed7f`, `cmp $0x2000,%rax` at `0x63aed85`, `ja 0x63aedc0` at `0x63aed8b`. Page at most `0x2000` returns via the shared epilogue at `0x63aed8d` and `ret` at `0x63aedb5` with no table work.
- Null-context gate: `test %rdi,%rdi` at `0x63aed72`, `je 0x63aee90` at `0x63aed75` — the bin_table_init site is entered only when the context is null.
- Loop: `lea 0x1b0(%rdi),%r13` (table) at `0x63aed4a`; cursor `rbx = page(0x8(%rdx)) + 0x1000`, end `r14 = page(0x8(%rdx)) + page(0x10(%rdx)) - 0x2000`; cursor steps `0x1000` per page; exits `jb 0x63aed8d` at `0x63aeddd` and `0x63aee12`.
- Constant: `movabs $0xe8000000000000,%r15` at `0x63aeddf` (same constant as #306); stored per page at `mov %r15,-0x8(%rax)` at `0x63aee0b`.
- Lookup per page: top index `(cursor >> 0x1a) & 0xf0`, high bits `cursor & 0xffffffffc0000000`, second level `(cursor >> 0x9) & 0x1ffff8 + table + 0x8`; top-level compare `cmp %rdi,%rcx` at `0x63aee42`; mismatch falls to the scan at `0x63aee47`.
- Scan (8 slots, table+`0x100` in `r13`, key in `rcx`): compares at `0x63aee4e`, `0x63aeec3`, `0x63aef15`, `0x63aef3c`, `0x63aef48`, `0x63aef77`, `0x63aef87`, `0x63aefaa` (slot 7 compares memory directly, `cmp 0x170(%r13),%rcx`). All normal-operand; 0 reversed-operand compares. Slot-0 inline block `0x63aee53..0x63aee83`, shared move-to-front block at `0x63aeec8` (`r9d` = previous slot index, `eax` = slot index, shift `*16`).
- Bin_table_init site: `0x63aeea1` (block `0x63aee90`): `lea 0x10(%rsp),%r13`, `mov %r13,%rdi`; `rdx` saved to `0x8(%rsp)` and `rsi` saved to `(%rsp)` across the call, restored after; rejoin `jmp 0x63aed7b`; preceding instruction `nopl` at `0x63aee88`.
- Lu-miss site: `0x63aefcd` (block `0x63aefb7`): `r8d` = 1, `r9d` = 0, `rdi` = context in `r12`, `rsi` = entry `rsi` (saved/restored via `(%rsp)`), `rdx` = scan table in `r13`, `rcx` = page cursor in `rbx`; return value in `rax` used directly as the second-level pointer; rejoin `jmp 0x63aee00`.
- Calls: `0x63aeea1` -> `0x63d9880` (bin_table_init), `0x63aefcd` -> `0x63d9700` (lu-miss handler), `0x63aef60` -> `0x63f0d70` (`__stack_chk_fail`).
- Return value: `eax` = 0 on the plain path; after a scan hit `eax` holds the last move-to-front slot index (as in #305).
- No `shl/sar $0x10` + mask transform, no node-resolution tables (`0x65096c0`/`0x6511780`), no size tables (`0x6727a00`/`0x67277c0`) anywhere in this FDE.
- Census: `.rela.dyn` 60,723 total / 59,534 RELATIVE (readelf -W), `.rela.plt` 278; raw `0xe8` census 108 total (tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17), this FDE raw 1.
- Disjointness: range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records, 0 skipped; window overlaps no prior range (verifier run figure in README.md).

## Implementation and comparison

Not yet implemented. This packet is observation only; no Rust reconstruction is claimed.

## Results and limitations

- Verifier: exit 0, 110 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md`.
- Disjointness: verifier scanned 63,068 priors, 0 skipped, NONE (deduplicated figure 62,270 after removing 798 within-file duplicate ranges).
- Unknowns: caller-side meaning of entry `rsi`; meaning of the constant `0xe8000000000000` beyond the write site; semantics of the stored per-page entry.
- Correction carried forward: the #298–#305 surveys listed this window with 2 lu-miss sites; packet #306 proved by objdump census it has 1 (`0x63aefcd`). This packet's own census re-verifies the corrected figure.
- Next question: packet #308 decodes `0x63aefe0..0x63af45f` (1151 bytes, 1 bin_table_init site `0x63af198`, 2 lu-miss sites, 1 ret, 0 bsr); fall-through `0x63af460..0x63afba4`, `0x63afc60..0x63b0324`, `0x63bc490..0x63bc728`, `0x63bc730..0x63bcb12`, `0x63c2f00..0x63c3328`.
