# RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall-plainrsp: how does the thirteenth 1-raw bin_table_init caller resolve four second-level pointers, and why does it always run all four walks?

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall-plainrsp
- Target release and full SHA-256: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation
- Scope included and excluded: the FDE `0x63afc60..0x63b0324` only (1732 bytes, 342 strict mnemonic lines). Included: the null-context bin_table_init site (plain `%rsp`), the four walks and their second-level pointer stores, the four 8-slot move-to-front scans, the four lu-miss sites, the canary epilogue and the `eax` return convention. Excluded (cited, not claimed): the bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss handler `0x63d9700..0x63d987b` (#215), the prev/next FDEs, the caller-side meaning of entry `rsi`/`r8d`/`r9d`, and the meaning of the four resolved pointers beyond the store sites.

## Reproduce

Working directory: a worktree of upstream main `05bc2de303c05525b71e7e257426e741bc66a390`. Static analysis only; the binary is never executed.

- FDE bounds: own `.eh_frame` parse (135,313 FDEs; CIE pointer relative to the CIE_id field, rec+4; fixed 4-byte range fields, not ULEB; FDE list sorted before bisect). Prev FDE `0x63afbb0..0x63afc54`, gap 12 bytes all `0xcc`; next FDE `0x63b0330..0x63b03b2`, padding 12 bytes all `0xcc`.
- Disassembly: `objdump -d --start-address=0x63afc60 --stop-address=0x63b0324 artifacts/node/115/hl-node` (exhibit `bintableinit_caller_4walk_resolveall_plainrsp_1site.objdump.txt`).
- Bytes: raw binary slice `0x63afc60..0x63b0324` (exhibit `bintableinit_caller_4walk_resolveall_plainrsp_1site.hex`, raw bytes, not hex text).
- Verifier: `python3 tools/node115_lu_bintableinit_caller_4walk_resolveall_plainrsp_1site.py` (exit 0, 205 checks, 0 failures).
- Tests: `python3 tests/test_node115_lu_bintableinit_caller_4walk_resolveall_plainrsp_1site.py` (exit 0, 12 checks, 0 failures; tamper controls run first).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md` on a pristine checkout. Full `make test` not run (584 files; declared in README.md).

## Evidence

Addresses are virtual addresses (VA). `.text` file offset = VA - 0x1000. Strict count = mnemonic lines matching `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (lowercase-start mnemonic).

- Window: `0x63afc60..0x63b0324`, 1732 bytes, 342 strict lines, 6 calls, 1 ret at `0x63afe10`, 0 bsr, 0 lock add/sub, 55 jumps, all inside the window, no tail-jump exit.
- Frame: `endbr64` at `0x63afc60`; pushes r15/r14/r13/r12/rbp/rbx; `sub $0x198,%rsp` at `0x63afc84`; canary at `0x188(%rsp)` (stored at `0x63afc94`, checked against `%fs:0x28` at `0x63afdf0`, mismatch jumps to `__stack_chk_fail` at `0x63b031f` via `jne` at `0x63afdf9`).
- Entry: `rdi` = context (kept in `r13`), `rsi` = live input (kept in `r14`, passed to all four lu-miss calls; overwritten only on the scan-D slot-0 hit path at `0x63aff18` and the scan-D shared block at `0x63affd7`), `rdx` = struct pointer (kept in `rbp`; the four result slots are `0x0/0x8/0x10/0x18(%rbp)`), `rcx` (kept in `r15`; `0x8(%rcx)` is the walk-1 key, `0x10(%rcx)` feeds the walk-2 derived key), `r8` (kept in `r12`; `0x8(%r12)` is the walk-3 key, `0x10(%r12)`/`0x8(%r12)` feed the walk-4 derived key).
- Null-context gate: `test %rdi,%rdi` at `0x63afc9e`, `je 0x63afe18` at `0x63afca1` — the bin_table_init site is entered only when the context is null.
- Bin_table_init site: `0x63afe1e` (block `0x63afe18`): `mov %rsp,%rbx`, `mov %rbx,%rdi` — plain `%rsp`, no `lea`, no save/restore (first plain-`%rsp` site in the 1-raw chain); `rsi` lives in callee-saved `r14` across the call; rejoin `jmp 0x63afca7`; preceding instruction `nopl` at `0x63afe11`.
- Table base in `rbx`: `lea 0x1b0(%rdi),%rbx` at `0x63afc7d` on the normal path; on the null-context path the bti block overwrites `rbx` with `mov %rsp,%rbx`, so the four walks and four scans run against the stack-temp table.
- Stack scratch: none — no `rep stos`, no stack save/restore anywhere in this FDE; the frame is `sub $0x198,%rsp` with the canary at `0x188(%rsp)`; the bti table is the stack itself (plain `%rsp` via `rbx`).
- Walk 1: key = `0x8(%r15)` (`mov 0x8(%r15),%rax` at `0x63afca7`); top index `(key >> 0x1a) & 0xf0` (`shr $0x1a,%rax` at `0x63afcb1`, `and $0xf0,%eax` at `0x63afcb5`, `add %rbx,%rax` at `0x63afcc8`), high bits `key & 0xffffffffc0000000` (`and` at `0x63afcba`), page `key & 0xfffffffffffff000` (`and` at `0x63afcc1`), top-level compare `cmp %rsi,%rdi` at `0x63afcce`; mismatch falls to scan A at `0x63afe30`; second level `(key >> 0x9) & 0x1ffff8 + table + 0x8` (`shr $0x9,%rcx` at `0x63afcd7`, `and $0x1ffff8,%ecx` at `0x63afcdb`, `add 0x8(%rax),%rcx` at `0x63afce1`); second-level pointer stored at `mov %rax,0x0(%rbp)` at `0x63afce8`. No null test — walk 2 always runs.
- Walk 2: derived key `page(0x10(%r15)) + page(0x8(%r15)) - 0x1000` (`lea -0x1000(%rdi,%r15,1),%r11` at `0x63afd02`); top-level compare `cmp %rsi,%rcx` at `0x63afd26`; mismatch falls to scan B at `0x63afe70`; second-level pointer stored at `mov %rax,0x8(%rbp)` at `0x63afd41`. No null test — walk 3 always runs.
- Walk 3: key = `0x8(%r12)` (`mov 0x8(%r12),%rax` at `0x63afd45`); top-level compare `cmp %rdi,%r15` at `0x63afd6d`; mismatch falls to scan C at `0x63afeb8`; second-level pointer stored at `mov %rax,0x10(%rbp)` at `0x63afd87`. No null test — walk 4 always runs.
- Walk 4: derived key `page(0x10(%r12)) + page(0x8(%r12)) - 0x1000` (`lea -0x1000(%r15,%r12,1),%rcx` at `0x63afda3`); top-level compare `cmp %rdi,%r11` at `0x63afdc7`; mismatch falls to scan D at `0x63aff00`; second-level pointer stored at `mov %rax,0x18(%rbp)` at `0x63afde4`.
- No null tests anywhere: there is no `test %rax,%rax` and no `cmpq $0x0` in this FDE, so all four walks always run and all four slots are always written (unlike #309, where walks 2 and 4 were skipped on a null second-level pointer).
- Scan A (8 slots, table+`0x100` in `rbx`, key in `rdi`): compares at `0x63afe30` (`cmp 0x100(%rbx),%rdi`), `0x63aff46`, `0x63b00e1`, `0x63b00f4`, `0x63b0107`, `0x63b011a`, `0x63b012d`, `0x63b013a` (slot 7 compares memory directly, `cmp 0x170(%rbx),%rdi`). 0 reversed-operand compares. Slot-0 inline block `0x63afe3d..0x63afe6b`, shared move-to-front block at `0x63aff53` (`r8d` = slot index, `r9d` = index-1, shift `*16`).
- Scan B (8 slots, table+`0x100` in `rbx`, key in `rcx`): compares at `0x63afe70` (`cmp 0x100(%rbx),%rcx`), `0x63b007e`, `0x63b0292`, `0x63b02a5`, `0x63b02b8`, `0x63b02cb`, `0x63b02de`, `0x63b02eb` (slot 7 compares memory directly, `cmp 0x170(%rbx),%rcx`). 0 reversed-operand compares. Slot-0 inline block `0x63afe7d..0x63afeac`, shared move-to-front block at `0x63b008b`.
- Scan C (8 slots, table+`0x100` in `rbx`, key in `r15`): compares at `0x63afeb8` (`cmp 0x100(%rbx),%r15`), `0x63b0015`, `0x63b0201`, `0x63b0213` (reversed, `cmp %r15,0x130(%rbx)`), `0x63b0225` (reversed, `cmp %r15,0x140(%rbx)`), `0x63b0237`, `0x63b0249`, `0x63b0256` (slot 7 compares memory directly, `cmp 0x170(%rbx),%r15`). Two reversed-operand compares (slots 3, 4). Slot-0 inline block `0x63afec5..0x63afef3`, shared move-to-front block at `0x63b0022`.
- Scan D (8 slots, table+`0x100` in `rbx`, key in `r11`): compares at `0x63aff00` (`cmp 0x100(%rbx),%r11`), `0x63affae`, `0x63b0172`, `0x63b0185`, `0x63b0198`, `0x63b01ab`, `0x63b01be` (reversed, `cmp %r11,0x160(%rbx)`), `0x63b01cb` (slot 7 compares memory directly, `cmp 0x170(%rbx),%r11`). One reversed-operand compare (slot 6). Slot-0 inline block `0x63aff0d..0x63aff3b` (the hit overwrites `r14` at `0x63aff18`), shared move-to-front block at `0x63affbb` (`r8d` = slot index, `r9d` = index-1; slot address built in `r13`, `r14` overwritten at `0x63affd7`).
- Lu-miss A: `0x63b0162` (block `0x63b0150`): `rcx` = `page(key1)` carried from the walk-1 page mask at `0x63afcc1` (no instruction in the lu-miss block or on the scan-A miss path writes `rcx`), `r8d` = 1, `r9d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbx`; return value in `rax` stored to `0x0(%rbp)`; rejoin `jmp 0x63afce8`.
- Lu-miss B: `0x63b0315` (block `0x63b0300`): `rcx` = derived key 2 in `r11` (`mov %r11,%rcx` at `0x63b0309`), `r8d` = 1, `r9d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbx`; return value in `rax` stored to `0x8(%rbp)`; rejoin `jmp 0x63afd41`.
- Lu-miss C: `0x63b0282` (block `0x63b0270`): `rcx` = `page(key3)` carried from the walk-3 page mask at `0x63afd60` (no instruction in the lu-miss block or on the scan-C miss path writes `rcx`), `r8d` = 1, `r9d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbx`; return value in `rax` stored to `0x10(%rbp)`; rejoin `jmp 0x63afd87`.
- Lu-miss D: `0x63b01f2` (block `0x63b01e0`): `rcx` = derived key 4, carried in `rcx` from the `lea` at `0x63afda3` (no instruction in the lu-miss block or on the scan-D miss path writes `rcx`), `r8d` = 1, `r9d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbx`; return value in `rax` stored to `0x18(%rbp)`; rejoin `jmp 0x63afde4`.
- The lu-miss argument convention is reversed from #309: here `r8d` = 1 and `r9d` = 0 (`mov $0x1,%r8d` + `xor %r9d,%r9d` in every block); #309 had `r9d` = 1 and `r8d` = 0.
- Calls: `0x63afe1e` -> `0x63d9880` (bin_table_init), `0x63b0162` -> `0x63d9700` (lu-miss handler), `0x63b01f2` -> `0x63d9700` (lu-miss handler), `0x63b0282` -> `0x63d9700` (lu-miss handler), `0x63b0315` -> `0x63d9700` (lu-miss handler), `0x63b031f` -> `0x63f0d70` (`__stack_chk_fail`).
- Return value: `eax` = 0 at `ret` (`0x63afe10`). Entry `xor %eax,%eax` at `0x63afc9c`; the only other `%eax` writes are the four top-index `and $0xf0,%eax` (at `0x63afcb5`, `0x63afd1b`, `0x63afd54`, `0x63afdbc`), each `< 0x100`; the epilogue loads the canary into `rax` (`mov 0x188(%rsp),%rax` at `0x63afde8`) and subtracts `%fs:0x28` (`sub` at `0x63afdf0`), so `rax` is 0 on the non-fault path. There is no `sete`, no `mov $0x1,%eax`, and no null-flag epilogue — unlike #309, this routine does not report null slots in `eax`, and there is no lu-miss quirk: every handler return value is stored to a slot and never reaches `eax`. Full `%eax` write list: `0x63afc9c`, `0x63afcb5`, `0x63afd1b`, `0x63afd54`, `0x63afdbc`.
- No `shl/sar $0x10` + mask transform, no node-resolution tables (`0x65096c0`/`0x6511780`), no size tables (`0x6727a00`/`0x67277c0`) anywhere in this FDE.
- Census: `.rela.dyn` 60,723 total / 59,534 RELATIVE (readelf -W), `.rela.plt` 278; raw `0xe8` census 108 total (tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17), this FDE raw 1.
- Disjointness: range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records, 0 skipped; window overlaps no prior range (verifier run figure in README.md).

## Implementation and comparison

Not yet implemented. This packet is observation only; no Rust reconstruction is claimed.

## Results and limitations

- Verifier: exit 0, 205 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md`.
- Disjointness: verifier scanned 65,594 priors, 0 skipped, NONE (deduplicated figure 64,766 after removing 828 within-file duplicate ranges).
- Unknowns: caller-side meaning of entry `rsi`/`r8d`/`r9d`; meaning of the four resolved pointers beyond the store sites; why the slot-0 compares use the reversed operand order in all four scans while slots 1–7 (except scan C slots 3–4 and scan D slot 6) use the normal order.
- Correction carried forward: the #298–#305 surveys listed packet #307's window with 2 lu-miss sites; packet #306 proved by objdump census it has 1 (`0x63aefcd`). This packet's own census re-verifies the corrected figure.
- Next question: packet #311 decodes `0x63bc490..0x63bc728` (664 bytes, 1 bin_table_init site `0x63bc5e5`, 1 lu-miss site, 1 ret, 0 bsr); fall-through `0x63bc730..0x63bcb12`, `0x63c2f00..0x63c3328`.
