# RE-001-node115-lu-bintableinit-caller-2sites-lookup-10rsp: lu bin_table_init 10rsp lookup walk caller, 2 sites

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-lookup-10rsp
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + byte-level census, no execution)
- Scope included and excluded: included — the single FDE
  0x63d61a0..0x63d6575 and its two bin_table_init sites, two lu-miss
  sites, two 8-slot scans, key-helper call, lock add, and single ret.
  Excluded — the bin_table_init body (#262), the lu-miss handler
  (#215), the key helper body, all referenced tables (read only), and
  the neighboring FDEs.

## Reproduce

Working directory: the worktree root (one level above tools/ and tests/).
Static analysis only; the node binary is never executed.

- `objdump -d --start-address=0x63d61a0 --stop-address=0x63d6575 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_lookup_10rsp_2sites.py` (exit 0)
- `python3 tests/test_node115_lu_bintableinit_caller_lookup_10rsp_2sites.py` (exit 0)
- `make verify` (exit 0); `make catalogue-check` (exit 2, pre-existing
  `Stale catalogue: README.md` failure, also on a pristine checkout)

## Evidence

Original addresses and coordinate system: virtual addresses as shown by
objdump; `.text` file offset = VA − 0x1000, `.rodata` VA as-is,
`.data` VA − 0x3000. FDE bounds from a from-scratch `.eh_frame`
parse (PC-relative sdata4, fixed 4-byte range fields, CIE pointer
relative to the CIE_id field; three CIEs, two zPLR — the 'L'
augmentation entry is an encoding byte only, with no value; the
FDE list is sorted before any bisect-based enclosing lookup):
target FDE `0x63d61a0..0x63d6575` (981 bytes), previous FDE
`0x63d6060..0x63d6199` (gap 7 bytes, all `0xcc`), next FDE
`0x63d6575..0x63d6619` (padding 0). Total FDEs 135,313, reproduced
by this packet's own parse.

Raw disassembly is kept beside this record
(`bintableinit_caller_lookup_10rsp_2sites.objdump.txt`); raw bytes
are kept as `bintableinit_caller_lookup_10rsp_2sites.hex` (raw
binary bytes, not hex text). Strict mnemonic-line count 199, calls
6, ret 1, bsr 0, lock add 1, lock sub 0. Call targets verified by
rel32: key helper `0x6364880` at `0x63d61e5`, bin_table_init
`0x63d9880` at `0x63d62e0` and `0x63d6345`, lu-miss `0x63d9700`
at `0x63d64c9` and `0x63d6566`, `__stack_chk_fail` `0x63f0d70`
at `0x63d6570`. All 32 jump instructions target inside the window.
Analysis was complete for this FDE; no range was truncated.

## Implementation and comparison

Not yet implemented/measured. This packet is an observation packet
only: no Rust implementation, no Cargo graph, no equivalence claim.
The verifier is a static byte-read checker, not a reimplementation.

## Results and limitations

- 66 verifier checks pass, 0 fail; 11 unit-test checks pass, 0 fail.
- Disjointness: range-only collector over the merged tree plus all
  prior `hl-wt-calls*` worktree records; window overlaps no prior
  range (verifier: 53,806 priors scanned, 0 skipped, NONE).
- Remaining unknowns: the key helper's key derivation, the
  bin_table_init body, the lu-miss handler's internals, and the
  contents of the referenced tables (`.bss` has no file content;
  only mechanism is claimed, never values).
- Gate coverage: this packet covers one FDE only; it does not cover
  the neighboring FDEs, the remaining 2-raw candidate, or the
  1-raw tier.
- Next question: the last surviving 2-raw candidate
  `0x63ed8b0..0x63edf05` (survey figures: 1621 bytes, 2
  bin_table_init sites, 2 lu-miss sites, 1 ret, 2 bsr; claim status
  NONE over all prior exhibits in this build's survey; census to be
  re-verified by program in #297). After it, the 1-raw tier
  (17 FDEs) remains.
