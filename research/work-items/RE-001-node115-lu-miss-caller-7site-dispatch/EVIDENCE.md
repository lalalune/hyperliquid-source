# RE-001-node115-lu-miss-caller-7site-dispatch: lu-miss caller with seven miss sites (first lu-miss-only window)

- Component ID: RE-001-node115-lu-miss-caller-7site-dispatch
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation
- Scope included and excluded: included — the single FDE `0x635c6d0..0x635de25` (5973 bytes, 1220 strict lines), its entry frame, size class, single walk (re-entered per element), two extract shapes, nine 8-slot move-to-front scan loops, seven lu-miss sites, dispatcher call census, exit (one ret, `rax` = 0). Excluded — the lu-miss handler body, the bin_table_init body, the second miss handler body (not called from this FDE), the lock-wait helper, all dispatcher callee bodies, the prev/next FDEs, runtime contents of `.bss`/`.data` objects, and the entry inputs' caller-side meaning.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at upstream main `05bc2de30` (local branch `codex/re-004-calls319-115`). Commands (all read-only against the binary):

- `objdump -d --start-address=0x635c6d0 --stop-address=0x635de25 artifacts/node/115/hl-node` (exhibit `lu_miss_caller_7site_dispatch.objdump.txt`; 1220 strict lines by the regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_7site_dispatch.py` (static verifier, exit 0)
- `python3 tests/test_node115_lu_miss_caller_7site_dispatch.py` (own unit tests, exit 0)
- `make verify` (exit 0; 559 manifests, 7159 entries), `make catalogue-check` (exit 2, pre-existing `Stale catalogue: README.md`, also on a pristine checkout)

Tool versions: system `objdump` (GNU binutils), Python 3.12, `readelf -r -W` for relocation counts. No node execution anywhere; no side effects beyond the packet files.

## Evidence

- Coordinates: virtual addresses throughout; `.text` file offset = VA − 0x1000 (`.hex` exhibit is the raw 5973-byte slice at file offset `0x635b6d0`). FDE bounds from an own `.eh_frame` parse (135,313 FDEs total): `0x635c6d0..0x635de25`; prev FDE `0x635a7a0..0x635c6c7` (#318 window, gap 9, all `0xcc`); next FDE `0x635de30..0x635ded5` (165 bytes, padding 11, all `0xcc`; starts `endbr64`, `cmp $0x1000,%rsi` at `0x635de34`).
- Entry: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx interleaved with the entry movs, `sub $0x88,%rsp`, canary `%fs:0x28` -> `0x78(%rsp)`. `rdi` -> `r12` (walk key), `rsi` -> `r14` (size input), `edx` -> `r13d` (flags), `rbx` is the TLS-derived context base. No entry null guard; no lock-add walk entry.
- TLS flag byte `%fs:0x330(%rbx)` checked at `0x635c705`; context helper `0x63ef8e0` called once at `0x635ccb8` from the init block (`rdi` = `rbx`, `rsi` = 1).
- Size class: byte table `0x67277c0` (`(r14+7)>>3`), size table `0x6727a00`, flag `0x6713606`, thresholds `$0x1000` / `$0x3800`; 9 `bsr` power-of-two roundings. No `$0xe7` gate in this window.
- Walk: single, table `rbx` + `0x1b0`, key `r12`; top index `(key>>0x1a)&0xf0`, high bits `key & 0xffffffffc0000000`, compare at `0x635cb31`, mismatch to scan `0x635d762`; second level `(key>>0x9)&0x1ffff8 + table + 0x8` into `rsi` at `0x635cb51`; nine top-index setups, seventeen second-level derefs.
- Extracts: `shl`/`sar $0x10` + `and` feeding `0x63be4d0` (at `0x635cb70` and `0x635d0dd`) and `0x63bd6c0` (at `0x635cd7a` and `0x635d53a`, the latter fed by the #314 window output in `0x10(%rsp)`); four inline `shr $0x30` extracts (`%r8` at `0x635d05b`, `%r14` at `0x635d19d`, `%rax` at `0x635d4a6`, `%r13` at `0x635d67f`). No `0x63be540` call.
- Scan: nine 8-slot move-to-front loops, table+`0x2b0` in `rbx`, key in the walk-key high bits; nine slot-0 compares, nine loop compares, 0 reversed-operand compares; exhaustion counters `r11`/`r11`/`r10`/`r14`+`r15`+`rdi`/`rdi`/`rdi`/`r8` == 8, one per loop, with the fourth miss block shared by three loops.
- Lu-miss sites (7): `0x635db78`, `0x635dc13`, `0x635dc48`, `0x635dce3`, `0x635dd28`, `0x635ddda`, `0x635de17` -> `0x63d9700`; all `rdi` = `rbx`, `rsi` = `0x6511a00` (`.bss`), `rdx` = `lea 0x1b0(%rbx)`, `rcx` = `r12`, `r8d` = 1, `r9d` = 0. Sites 6 and 7 save/restore `r10` in `(%rsp)` around the call. `rcx` provenance by CFG reachability (only the entry `r12` write reaches any miss site).
- Second-handler sites (0): `0x634ebb0` is not called from this FDE.
- Dispatcher: 31 calls, 17 distinct direct targets + 1 indirect (GOT `0x64ffb30`); #314 x1, `0x63c3330` x2, `0x6363260` x3, `0x63eb870` x2, `0x63ead50` x2, `0x63be4d0` x2, `0x63bd6c0` x2. PLT: `abort` 1, `__stack_chk_fail` 1.
- Exits: one `ret` at `0x635c886` (`rax` = 0 — the canary check leaves `rax` 0 and nothing writes `rax` before the `ret`); no tail-jump exit. 200 jumps, zero outside the window.
- Raw `0xe8` censuses: lu-miss 168 sites / 53 FDEs (this FDE 7); bti 108 sites / 42 FDEs (this FDE 0); second-handler 64 sites (this FDE 0; next candidate 3). `.rela.dyn` 60,723 total / 59,534 RELATIVE; `.rela.plt` 278. `.bss` `0x64ffe40..0x6728924` (exact end asserted); 9 referenced addresses inside.
- Analysis was complete for the claimed window; the dispatcher callees' bodies, the `.bss` contents, and the entry inputs' caller-side meaning were not established.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed for this window. The static verifier (`tools/node115_lu_miss_caller_7site_dispatch.py`) re-checks every figure above from the binary and the exhibits by program, with tamper controls in the unit tests (hex flip, strict-count change, call-site change, injected overlap — each makes the temp-copy verifier fail; the clean temp copy passes).

## Results and limitations

- Verifier: exit 0 (303 checks, 0 failures), fresh post-seal, priors scanned 73,176, 0 skipped, disjointness NONE.
- Own unit tests: exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2 (pre-existing stale catalogue, not a regression). Full `make test` not run (584 files; declared deviation).
- Limitations: the exit value is 0 by construction of the epilogue (not a computed result); the dispatcher callees' outputs and the entry inputs' caller-side meaning are not established. The next question is packet #320 on `0x635e2e0..0x635f315` (4149 bytes, 1 lu-miss site, 3 second-handler sites, bsr 5), verified disjoint from all priors and from this window.
