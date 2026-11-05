# RE-001: lu bin_table_init bsr-size walk caller, 2 sites

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-walk-bsr
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly census, byte comparison, FDE
  bounds); helper-body semantics are cited, not claimed
- Scope included and excluded: FDE `0x63ed8b0..0x63edf05` only. The
  bin_table_init body, the lu-miss handler, all helper bodies, and all
  tables/globals are cited or read, not claimed. Neighboring FDEs are
  not decoded here.

## Reproduce

Static analysis only; the node binary is never executed. In the worktree
root, with `objdump` (binutils) and `readelf`:

- `objdump -d --start-address=0x63ed8b0 --stop-address=0x63edf05
  artifacts/node/115/hl-node` reproduces the objdump exhibit
  (338 strict mnemonic lines).
- `readelf -r -W artifacts/node/115/hl-node` reproduces the relocation
  census (`.rela.dyn` 60,723 total / 59,534 RELATIVE, `.rela.plt` 278).
- `python3 tools/node115_lu_bintableinit_caller_walk_bsr_2sites.py`
  runs the static verifier (byte reads only).
- `python3 tests/test_node115_lu_bintableinit_caller_walk_bsr_2sites.py`
  runs the unit tests (tamper controls first, then the clean temp-copy
  verifier run).

## Evidence

Original addresses are virtual addresses (VA); `.text` file offset is
VA − 0x1000, `.rodata` is VA as-is, `.data` is VA − 0x3000. FDE bounds
come from an own `.eh_frame` parse (PC-relative sdata4 encoding,
fixed 4-byte range fields, CIE pointer relative to the CIE_id field;
three CIEs, two zPLR; the `L` augmentation entry is an encoding byte
only with no value; FDE list sorted before bisect; 135,313 FDEs
total, reproduced). Previous FDE `0x63ed870..0x63ed8a4` (gap 12 bytes,
all `0xcc`); next FDE `0x63edf10..0x63ee0a0` (padding 11).

Window census (from the objdump exhibit, never copied from a prior
packet): 338 strict lines, 13 calls, 1 ret, 2 bin_table_init sites
(`0x63edb88`, `0x63edc65`, both `lea 0x10(%rsp)` in-block), 2 lu-miss
sites (`0x63ede59`, `0x63edef6`), 2 bsr (`0x63edb11`, `0x63edd02`),
0 lock sub, 1 lock add (`0x63eda62`), 55 jump instructions, all
targeting inside the window, 0 tail jumps. Raw `0xe8` census (byte
scan for `e8` with rel32 target `0x63d9880`, grouped by enclosing
`.eh_frame` FDE): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12,
1x17; this FDE holds 2 raw sites, matching its 2 objdump sites.

Size computation: entry inputs from `0x6728858` and `0x6728860` (+
`0x797`, rounded down to a multiple of 8), guarded by `cmp $0x3800`,
`cmp $0x1000`, and a rounded-size `cmp $0x1000`, with two bsr
overflow arms (0x63edae0, 0x63edce8) that rejoin the size-class
computation. Threshold table `0x67277c0` indexed by
`(rounded_size + 7) >> 3`; size-class byte indexes node-resolution
table `0x6727a00`; values above `0x3fff` take the page-rounding arm.

Walk: helper `0x6365150` at `0x63ed9a9` derives the key (kept in
rbp); two-phase context+`0x1b0` table walk with 8-slot
move-to-front scans (scan B on the r11 table, scan A on the rdx
table), node resolution through `0x6727a00` indexed by
`(value >> 0x30)`, `lock add %r14,0x38(%r11)` at `0x63eda62`, and
tail calls (`0x63e91c0`, `0x63ec4c0`, `0x6352fc0`, `0x63ec7a0`,
and #261's routine twice). Full site/scan tables are in records.json.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in
this packet; it is an evidence packet only. The static verifier
re-derives every census figure from the binary and the exhibits and
checks disjointness against all prior packet exhibits.

## Results and limitations

- Static verifier: exit 0 (see README for the final check count).
- Own unit tests: exit 0 (see README for the final check count).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.
- Helper-body semantics (including the null-return semantics of
  `0x6365150` and the `0x63e91c0` vs `0x63ec690` structural-sameness
  question) are not decoded here.

Next question: the 1-raw tier (17 FDEs) is the next frontier after
this packet exhausts the 2-raw tier; its survey belongs to packet
#298, verified there, not assumed here.
