# RE-001-node115-lu-bintableinit-caller-4sites-walk-10rsp-locksub: bounded question

- Component ID: lu bin_table_init caller FDE (node-115 lookup chain, thirteenth caller)
- Target release and full SHA-256: node-115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390` (fetch-confirmed at build time)
- Claim status: observation (disassembly + byte census only; no runtime values)
- Scope included and excluded: included — the single caller FDE
  `0x63ec900..0x63ed06d` (1901 bytes), its 4 bin_table_init sites, 4 lu-miss
  sites, scan shapes, lock-sub node resolution, and the raw-e8 tier survey.
  Excluded — callee FDE internals beyond call-site patterns, the 2-raw/1-raw
  tiers, static leaves, named-only callee families, runtime `.bss` values.

## Reproduce

Working directory: the worktree root. Targeted objdump only (no full-.text
dump, no execution):

```
objdump -d --start-address=0x63ec900 --stop-address=0x63ed06d \
  artifacts/node/115/hl-node
python3 tools/node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py
python3 tests/test_node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py
```

Tool versions: system objdump/readelf, python3. No side effects; the binary
is only read.

## Evidence

Original addresses are virtual addresses (VA). Coordinate system: `.text`
file offset = VA − 0x1000, `.rodata` = VA as-is, `.data` = VA − 0x3000.
Boundaries validated from `.eh_frame` (PC-relative sdata4, fixed 4-byte
range fields, not ULEB; CIE pointer relative to the CIE_id field, rec+4).
Previous FDE `0x63ec7a0..0x63ec900` (gap 0), next FDE
`0x63ed070..0x63ed089` (padding 3 bytes `0xcc`).

Raw files beside this record: `bintableinit_caller_walk_10rsp_locksub_4sites.hex`
(raw binary bytes of the window, 1901 bytes) and
`bintableinit_caller_walk_10rsp_locksub_4sites.objdump.txt` (targeted
objdump). Strict count 407 (address + bytes field + tab + mnemonic
starting with a lowercase letter). Call census: 17 total / 4 bin_table_init
/ 4 lu-miss / 0 ret / 0 bsr / 1 lock sub (`lock sub %r9,0x38(%r8)` at
`0x63eca2f`). Callers/callees: bin_table_init body `0x63d9880..0x63d9a64`
(#262, cited), lu-miss handler `0x63d9700..0x63d987b` (#215, cited),
tail-jump target `0x6360ed0`, ordinary call targets `0x63637f0`,
`0x63bd6c0` (#279), `0x6363260`, `0x6364400` (getter family, context only),
prologue callees `0x63ead50`, `0x63eb870`.

Analysis was complete for this window (not timed out, not range-limited
beyond the FDE itself). The raw-e8 tier survey scanned all of `.text`
(grouped by enclosing `.eh_frame` FDE from the readelf list of 135,313
FDEs): total 108, tiers 10×1 / 8×1 / 6×2 / 5×1 / 4×8 / 3×0 / 2×12 / 1×17.
Parser note: CIE offsets are hex — a `\d+` CIE pattern undercounts FDEs
(this explains an earlier 82,631 figure); use `[0-9a-f]+`.

## Implementation and comparison

Not yet implemented/measured: no independent Rust path is claimed for this
window; this packet is observation-only evidence. No Cargo graph, no
build comparison, no equivalence claim.

## Results and limitations

Machine-readable metrics: 1901 bytes, 407 strict, 17 calls, 0 ret, 0 bsr,
1 lock sub, 4 + 4 sites, disjointness NONE over prior ranges, verifier and
unit tests green (see README for gate results). `make catalogue-check`
fails pre-existing on this base (`Stale catalogue: README.md`); full
`make test` (584 files) is not run by design — both stated honestly in
the README and body rather than claimed as passes.

What remains unknown: the 2-raw tier's objdump-verified site counts and
claim status per candidate; the getter family internals; runtime values of
any `.bss` byte; whether the four walk paths are four distinct callers or
one caller inlined four times.

Next question: packet #288's scout surveys the 2-raw tier (12 FDEs listed
in README), verifying each candidate's objdump site count and claim status
against prior exhibits before building.
