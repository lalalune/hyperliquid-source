# RE-001: lu lu-miss 1-site single-walk extract caller

- Component ID: RE-001-node115-lu-miss-caller-1site
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes.
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Claim status: observation
- Scope included and excluded: included — FDE `0x63495b0..0x6349775`
  only (single-walk lookup, inline five-field extract, single 8-slot
  move-to-front scan, one lu-miss site). Excluded — the lu-miss handler
  `0x63d9700..0x63d987b` (#215), the bin_table_init body
  `0x63d9880..0x63d9a64` (#262), the lock-wait helper `0x63bf680..0x63bf7ee`
  (#251), the neighboring FDEs, and the `.bss` object at `0x6511a00`
  (address use only; contents runtime-populated).

## Reproduce

Working directory: the repository root of the worktree (node #115).
Binary: `artifacts/node/115/hl-node` (SHA-256 above). No node
execution; static reads only.

- `objdump -d --start-address=0x63495b0 --stop-address=0x6349775 artifacts/node/115/hl-node`
  produces `lu_miss_caller_1site.objdump.txt` (100 strict mnemonic
  lines, counted with `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` — the bytes
  column in this objdump output is space-padded, so the old
  `[0-9a-f]+\t` form matches 0 lines).
- `python3 tools/node115_lu_miss_caller_1site.py` — static verifier,
  exit 0. Prior collection is I/O-bound (~3 min); an optional
  fingerprint-validated cache (`HL_PRIORS_CACHE`) reuses it across
  runs in one build and never changes the verdict.
- `python3 tests/test_node115_lu_miss_caller_1site.py` — unit tests,
  exit 0 (tamper controls first; the clean temp copy passes).
- `make verify` — exit 0 (559 evidence-packet manifests, 7159
  entries). `make catalogue-check` — exit 2, pre-existing `Stale
  catalogue: README.md`, also present on a pristine checkout.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Evidence

- Coordinates: virtual addresses; `.text` file offset = VA − 0x1000.
  Window `0x63495b0..0x6349775` = 453 bytes, verified against own
  `.eh_frame` parse (135,313 FDEs, sorted before bisect). Prev FDE
  `0x6349560..0x63495a5` (gap 11, all `0xcc`); next FDE
  `0x6349780..0x6349bd9` (padding 11, all `0xcc`).
- Raw disassembly: `lu_miss_caller_1site.objdump.txt` beside this
  record. Callers/callees: exactly one call, `0x634976b` →
  `0x63d9700` (lu-miss handler); no bin_table_init call, no helper
  call, no PLT call. One `ret` at `0x634962f`; 13 jumps, all inside
  the window; 0 `bsr`; 0 `lock`.
- Walk: top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, pointer into `rsi`.
- Extract: `shl`/`sar $0x10` + `and $0xffffffffffffff80`, five stores
  into the struct at `rbx` (`+0x0` 48-bit value, `+0x8` descriptor
  `>> 0x30`, `+0xc` (descriptor `>> 0x2`) `& 0x7`, `+0x10`
  (descriptor `>> 0x1`) `& 0x1`, `+0x11` descriptor `& 0x1`).
- Scan: 8 slots at table+`0x100`..`0x170` step `0x10`, key in `rsi`,
  all compares memory-first, 0 reversed; slot-0 inline block
  `0x6349639..0x6349667`, shared MTF block at `0x634967f`.
- Lu-miss block `0x6349758`: `rdi` = entry `rsi` (via `r10`),
  `rsi` = `0x6511a00` (`.bss`), `rdx` = entry table, `rcx` = entry
  key, `r8d` = 1, `r9d` = 0; rejoin `jmp 0x63495e9`. Provenance by
  exact miss-path write-set check (39 traced instructions).
- `.bss` is `0x64ffe40..0x6728924` (NOBITS, section size `0x228ae4`,
  exact end asserted by the verifier); `0x6511a00` lies inside.
- Raw-`0xe8` census for target `0x63d9700`: 168 sites in 53 FDEs,
  tiers 1x18, 2x14, 3x1, 4x11, 5x1, 6x2, 7x1, 8x1, 10x3, 13x1; this
  FDE holds 1 site. Raw-`0xe8` for target `0x63d9880`: 0 in this FDE.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278.
- Analysis was complete over the whole FDE; no timeout, no range
  limit.

## Implementation and comparison

Not yet implemented/measured: no Rust reimplementation in this
packet. The static Python verifier (`tools/`) re-derives every
figure from the binary and the exhibits (FDE bounds, strict/call
census, walk/extract/scan/lu-miss structure, miss-path write sets,
jump closure, rela counts, raw-e8 tiers, disjointness, slug
uniqueness, MANIFEST hashes) with tamper controls in the unit tests.

## Results and limitations

- Static verifier: exit 0. Own unit tests: exit 0. `make verify`:
  exit 0 (559 manifests, 7159 entries). `make catalogue-check`:
  exit 2, pre-existing failure, not a packet regression.
- Disjointness: the window overlaps no prior range (verifier:
  68,962 priors scanned, 0 skipped, NONE). The next candidate
  `0x6353a70..0x635582b` is likewise disjoint from all priors.
- Unknown: the entry `rsi` context's caller-side meaning, the
  `r8d`/`r9d` values' caller-side meaning, and the semantics of the
  five output fields beyond the store sites. The `.bss` contents at
  `0x6511a00` are runtime data and are not established.
- Next question: packet #315 decodes `0x6353a70..0x635582b` (7611
  bytes, 1 lu-miss site, 0 bin_table_init sites, 6 second-handler
  sites — the next lu-miss survivor in address order, also a
  survivor of the second miss handler `0x634ebb0`).
