# RE-001-node115-lu-miss-caller-4site-dispatch: lu-miss caller with four miss sites (first multi-site window)

- Component ID: RE-001-node115-lu-miss-caller-4site-dispatch
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation
- Scope included and excluded: included — the single FDE `0x635a7a0..0x635c6c7` (7975 bytes, 1720 strict lines), its entry frame, size class, single walk, three extract shapes, four 8-slot move-to-front scan loops, four lu-miss sites, two second-handler sites, dispatcher call census, exits (one ret + one tail-jump). Excluded — the lu-miss handler body, the bin_table_init body, the second miss handler body, the lock-wait helper, all dispatcher callee bodies, the #283 tail-jump target window, the prev/next FDEs, runtime contents of `.bss`/`.data` objects, and the entry inputs' caller-side meaning.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at upstream main `05bc2de30` (local branch `codex/re-004-calls318-115`). Commands (all read-only against the binary):

- `objdump -d --start-address=0x635a7a0 --stop-address=0x635c6c7 artifacts/node/115/hl-node` (exhibit `lu_miss_caller_4site_dispatch.objdump.txt`; 1720 strict lines by the regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_4site_dispatch.py` (static verifier, exit 0)
- `python3 tests/test_node115_lu_miss_caller_4site_dispatch.py` (own unit tests, exit 0)
- `make verify` (exit 0; 559 manifests, 7159 entries), `make catalogue-check` (exit 2, pre-existing `Stale catalogue: README.md`, also on a pristine checkout)

Tool versions: system `objdump` (GNU binutils), Python 3.12, `readelf -r -W` for relocation counts. No node execution anywhere; no side effects beyond the packet files.

## Evidence

- Coordinates: virtual addresses throughout; `.text` file offset = VA − 0x1000 (`.hex` exhibit is the raw 7975-byte slice at file offset `0x63597a0`). FDE bounds from an own `.eh_frame` parse (135,313 FDEs total): `0x635a7a0..0x635c6c7`; prev FDE `0x635a790..0x635a79b` (gap 5, all `0xcc`; 11-byte thunk `endbr64; xor %ecx,%ecx; jmp 0x635a7a0`); next FDE `0x635c6d0..0x635de25` (padding 9, all `0xcc`).
- Entry: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0xc8,%rsp`, canary `%fs:0x28` -> `0xb8(%rsp)`. `rdi` -> `rbx` (walk key), `rsi` -> `rbp` (context). Null guard splits the entry three ways (both non-null -> tail-jump to `0x6350210`; `rsi` == 0 and `rdi` != 0 -> walk path at `0x635a968`; otherwise -> TLS path at `0x635a825`).
- TLS flag byte `%fs:0x330` checked at `0x635a838`; context helper `0x63ef8e0` called at `0x635ac73` and `0x635b362`.
- Size class: byte table `0x67277c0` (`(rbp+7)>>3`, `cmp $0xe7`), size table `0x6727a00`, flag `0x6713606`, thresholds `$0x1000` / `$0x3800`; 7 `bsr` power-of-two roundings.
- Walk: single, table `rbp` + `0x1b0`, key `rbx`; top index `(key>>0x1a)&0xf0`, high bits `key & 0xffffffffc0000000`, compare at `0x635aa20`, mismatch to scan `0x635b222`; second level `(key>>0x9)&0x1ffff8 + table + 0x8` into `r10` at `0x635aa3d`; inline `shr $0x30` extract at `0x635aa55`.
- Extracts: `shl`/`sar $0x10` + `and` feeding `0x63be4d0` (at `0x635b2d3`) and `0x63bd6c0` (at `0x635b4df`); `0x63be540` x2 fed by #314 window output structs in stack temps; second inline `shr $0x30` at `0x635bd5b`.
- Scan: four 8-slot move-to-front loops, table+`0x2b0` in `rbp`, key `r11`; five slot-0 compares, five loop compares, 0 reversed-operand compares; exhaustion counters `r13`/`rsi`/`r8`/`r9` == 8, one per lu-miss block.
- Lu-miss sites (4): `0x635bebb`, `0x635c0d2`, `0x635c231`, `0x635c45f` -> `0x63d9700`; all `rdi` = `rbp`, `rsi` = `0x6511a00` (`.bss`), `rdx` = `0x8(%rsp)` (saved walk table), `rcx` = `rbx`, `r8d` = 1, `r9d` = 0. `rcx` provenance by CFG reachability (only the entry `rbx` write reaches any miss site; walk entry `0x635a968` reaches all four).
- Second-handler sites (2): `0x635b5ea`, `0x635bd35` -> `0x634ebb0`; `rdi` = `r12`, `rdx` = `0x64da4b0`, `rsi` = 0 at both (proven).
- Dispatcher: 103 calls, 33 distinct direct targets + 2 indirect (GOT `0x64ffb30`, `0x64ffb38`); #314 x2, #313 x2, #298 x2; `0x6364880` x13, `0x6353610` x12, `0x63e9cd0` x12, `0x63bd2c0` x8, `memset@plt` x5.
- Exits: one `ret` at `0x635ab53` (`rax` = `r11`, path-dependent: 0 on the errno path); one tail-jump exit at `0x635a80f` -> `0x6350210` (#283 window). 299 jumps, exactly one outside target (the tail-jump).
- Raw `0xe8` censuses: lu-miss 168 sites / 53 FDEs (this FDE 4); bti 108 sites / 42 FDEs (this FDE 0). `.rela.dyn` 60,723 total / 59,534 RELATIVE; `.rela.plt` 278. `.bss` `0x64ffe40..0x6728924` (exact end asserted); 14 referenced addresses inside.
- Analysis was complete for the claimed window; the dispatcher callees' bodies, the `.bss` contents, and the entry inputs' caller-side meaning were not established.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed for this window. The static verifier (`tools/node115_lu_miss_caller_4site_dispatch.py`) re-checks every figure above from the binary and the exhibits by program, with tamper controls in the unit tests (hex flip, strict-count change, call-site change, injected overlap — each makes the temp-copy verifier fail; the clean temp copy passes).

## Results and limitations

- Verifier: exit 0 (238 checks, 0 failures), fresh post-seal, priors scanned 72,333, 0 skipped, disjointness NONE.
- Own unit tests: exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2 (pre-existing stale catalogue, not a regression). Full `make test` not run (584 files; declared deviation).
- Limitations: exit value `rax` = `r11` is path-dependent (no single identity); the second-handler `rsi` at both sites is 0 (proven), but the dispatcher callees' outputs and the entry inputs' caller-side meaning are not established. The next question is packet #319 on `0x635c6d0..0x635de25` (5973 bytes, 7 lu-miss sites, 0 second-handler sites, bsr 9), verified disjoint from all priors and from this window.
