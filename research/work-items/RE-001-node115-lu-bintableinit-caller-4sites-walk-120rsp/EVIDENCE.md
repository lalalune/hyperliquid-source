# RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp: lu bin_table_init 120rsp walk caller, 4 sites

- Component ID: lu (lookup) bin_table_init caller chain, node-115
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390` (fetch-confirmed at build time)
- Claim status: observation (disassembly + byte census); register-use inference for argument roles; unresolved: whether the four walk paths are four distinct callers or one caller inlined four times
- Scope included and excluded: included: one FDE window `0x6350210..0x6352f5e`, its 4 bin_table_init sites, 13 lu-miss fallbacks, scan shape, size-class blocks, exits. Excluded: callee FDE internals, runtime data values, the remaining 107 static leaves, the next caller FDE `0x6365660..0x63673d9`.

## Reproduce

Working directory: a worktree of upstream main `05bc2de30` (branch `codex/re-004-calls283-115`). Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x6350210 --stop-address=0x6352f5e artifacts/node/115/hl-node` (targeted window only; no full-.text dump)
- `readelf --debug-dump=frames artifacts/node/115/hl-node` (FDE bounds; this window confirmed as `pc=0x6350210..0x6352f5e`, prev `0x634ffd0..0x635020a`, next `0x6352f60..0x6352fb6`)
- `python3 tools/node115_lu_bintableinit_caller_walk_120rsp_4sites.py` (exit 0)
- `python3 tests/test_node115_lu_bintableinit_caller_walk_120rsp_4sites.py` (exit 0)
- `make verify` (exit 0, 559 manifests, 7161 entries); `make catalogue-check` (exit 2, pre-existing `Stale catalogue: README.md` on the new base)
- `sha256sum -c` on the packet MANIFEST (all 7 entries OK)
- Full `make test` NOT attempted: 584 test files on the new base take hours and risk a VM-restart kill mid-run; no full-suite tally is claimed.

## Evidence

Coordinate system: VA as shown by objdump. `.text` file offset = VA - `0x1000`; `.rodata` = VA as-is; `.data` = VA - `0x3000`. `.hex` exhibits contain raw binary bytes, not hex text.

Validated boundaries: `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields): window `0x6350210..0x6352f5e` = 11598 bytes (`0x2d4e`, program arithmetic). Gap before 6 bytes (`0xcc`), padding after 2 bytes (`0xcc`). Frame `sub $0x2b8,%rsp`, canary `0x2a8(%rsp)`.

Raw disassembly is kept beside this record as `bintableinit_caller_walk_120rsp_4sites.objdump.txt` (targeted objdump, 2382 strict lines). Strict-line rule: address + bytes field + tab + mnemonic starting with a lowercase letter; byte-continuation lines excluded.

Callers/callees: 90 calls total; 4 to bin_table_init (`0x63d9880`, #262's body, cited not claimed) at `0x6350e15`, `0x6351683`, `0x6351aba`, `0x635223a`, all with rdi = `lea 0x120(%rsp)` under rbx == 0 branches; 13 to the lu-miss handler (`0x63d9700`, #215's FDE, cited not claimed) with shared shape rdi = rbx, rsi = `lea 0x6511a00`, r8 = 1, r9 = 0; 1 ret at `0x63504fc` (shared epilogue); 14 bsr instructions in repeated size-class blocks (e.g. `0x6350798`: bsr of `(2*size - 1)`, clamp to 7, minus 3, shift; thresholds `0x7000000000000000` and `0x4000` nearby). No `lock sub` refcount decrement is observed in this FDE; the `0x65096c0` table is read by index only.

Walk shape (entry, `0x63502c3..0x6350321`): top index `(key >> 0x1a) & 0xf0` into context + `0x1b0`; high bits `key & 0xffffffffc0000000` compared; second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`; node value resolved through the `0x6727a00` table indexed by `(value >> 0x30)`; insert path writes the new key and swaps the `0x100`/`0x108` fields of the table entry.

Scan shape: 8-entry array at walk-table + `0x100`, 16-byte entries; slot 0 (MRU head) never compared; slot 1 compared separately (e.g. `0x635145d`); slots 2..7 compared unrolled (e.g. `0x6351e74..0x6351ec9`, hit path `0x635146a`); hit swaps into slot 0; exhaustion falls to a lu-miss call. An indexed loop at `0x6351e05` (index r12 from 1, entries at context + `0x2b0`) shows the same hit-swap shape.

Source mapping evidence: none — the binary's symbol names are stripped to a single base label, so all names above are inferred from register use.

Analysis was complete for this window (not timed out, not range-limited beyond the FDE itself).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in this packet. The verifier is a static byte/census checker, not a reimplementation. Helper/data/relocation closure: `.rela.dyn` 60,723 entries total / 59,534 RELATIVE (stated distinctly); `.rela.plt` 278 entries counted separately. Fixture identities: the `.hex` exhibit is the exact 11598-byte window slice of the target binary; the `.objdump.txt` exhibit is the targeted objdump of the same window. Corruption controls: the unit tests flip one hex byte, change the strict count, change a call-site entry, and inject an overlapping range — each must fail the verifier (verified via JSON parse/modify/write tampers, not string replacement).

## Results and limitations

Machine-readable metrics with explicit denominators: strict 2382/2382 recount match; calls 90 = 4 bin_table_init + 13 lu-miss + 73 other; ret 1; bsr 14; disjointness NONE over 41,326 prior ranges, 0 overlaps (verifier collector recount at run time); raw-e8 census for target `0x63d9880`: 10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), 4 (#280), 4 (#281), 4 (#282), 4 (this FDE); remaining 4-raw FDEs: `0x6365660..0x63673d9`, `0x63d3080..0x63d379c`, `0x63d5940..0x63d605c`, `0x63ec900..0x63ed06d`.

What remains unknown: whether the four walk paths are four distinct callers or one caller inlined four times; runtime values of all data addresses; the per-scan mapping of all thirteen lu-miss sites to distinct walk variants (arguments and rejoins are listed, but variant attribution is not proven for every site).

No gate is requested beyond the packet's own verifier, unit tests, `make verify`, and the honestly reported `make catalogue-check` exit 2.

Next question: decode the next bin_table_init caller FDE `0x6365660..0x63673d9` (4 raw candidates, 7545 bytes).
