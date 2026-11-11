# RE-001-node115-lu-bintableinit-caller-6sites-dump: dump routine with six bin_table_init sites

- Component ID: node-115 lookup/dump caller FDE 0x63d4bbe..0x63d5428
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly-backed) for the FDE bounds,
  call census, site arguments, gates, file operations, and phase
  structure; inference for the dump-routine characterization and
  the return-value rule; unresolved for callee internals and
  runtime `.bss` values
- Scope included and excluded: included — the single FDE window
  0x63d4bbe..0x63d5428 and its call sites; excluded — callee
  FDE internals, runtime values, the 107 remaining static leaves,
  and the next caller FDE 0x63bd8c0..0x63be4ce

## Reproduce

Working directory: the packet worktree root. Static analysis
only; the target binary is never executed.

- `objdump -d --start-address=0x63d4bbe --stop-address=0x63d5428 artifacts/node/115/hl-node`
  regenerates the `.objdump.txt` exhibit up to its header lines
  (the tests strip header lines before comparing).
- The `.hex` exhibit is the raw binary slice at file offset
  VA - 0x1000 for `.text` (0x63d4bbe -> 0x63d3bbe), 2154 bytes.
- `python3 tools/node115_lu_bintableinit_caller_dump_6sites.py`
  runs the static verifier (byte reads only; exit 0).
- `python3 tests/test_node115_lu_bintableinit_caller_dump_6sites.py`
  runs the unit tests (9/9, tamper controls first).
- `make verify` and `make catalogue-check` run the repository
  gates; full `make test` is NOT attempted (584 test files).

## Evidence

Coordinate system: virtual addresses (VA) as shown by objdump;
`.text` file offset = VA - 0x1000; `.rodata` = VA as-is;
`.data` = VA - 0x3000. FDE bounds from `.eh_frame`
(PC-relative sdata4 encoding, fixed 4-byte range fields —
not ULEB). Raw bytes: see the `.hex` exhibit; disassembly:
see the `.objdump.txt` exhibit.

- FDE 0x63d4bbe..0x63d5428 (2154 bytes, 454 strict lines,
  69 calls, 1 ret at 0x63d5427, canary at 0xa08(%rsp),
  frame 0xa18, `__stack_chk_fail` call at 0x63d5411).
  Previous FDE ends exactly at the start (gap 0); next FDE
  starts exactly at the end (padding 0).
- Entry gates: `.bss` bytes 0x6713606 and 0x67123a0; state
  word 0x67157f4; mutex 0x67146e0; flag byte 0x6714708.
- File creation: creat() at 0x63d4c5c, path pointer `.bss`
  0x67147e0, mode 0x1a4 (= 0644), descriptor slot 0x4(%rsp);
  errno path via 0x63f0ad0 and error-report helper
  0x63bf5b6; abort@plt at 0x63d4c8d guarded by byte
  0x651174d; close@plt at 0x63d53de.
- bin_table_init sites (all rbp == 0 branches, target
  0x63d9880 claimed by #262): 0x63d4eed (rdi = r13),
  0x63d4f2b (rdi = lea 0x870(%rsp)), 0x63d50af (rdi = lea
  0x3f0(%rsp)), 0x63d50e7 (rdi = lea 0x570(%rsp)),
  0x63d5267 (rdi = r13), 0x63d529c (rdi = 0x8(%rsp) slot).
- Emit helper 0x63d481a: 14 sites, args (rbx struct,
  `.rodata` format, length, value pointer).
- Phase list heads: 0x6714728, 0x6714738, 0x6714718;
  refcount `lock sub` on 0x65096c0-table entries indexed
  by (leaf & 0xfff); second table 0x6727a00.
- No lu-miss handler calls (0 sites to 0x63d9700) and no
  radix-walk skeleton in this FDE.
- Raw-e8 census for target 0x63d9880 grouped by enclosing
  `.eh_frame` FDE: 10 (#275), 8 (#276), 6 (#277), 6 (this
  FDE), 5 (0x63bd8c0..0x63be4ce); this FDE's raw count
  equals its objdump-verified site count (6).
- `.rela.dyn`: 60,723 entries total, 59,534 of type
  RELATIVE (stated distinctly).
- Analysis is complete for this FDE window; no timeout.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
claimed for this FDE. The verifier regenerates the exhibit
bytes from the binary slice and recounts strict lines and
call targets independently; the tests compare regenerated
objdump output with header lines stripped and confirm every
tamper control fails the verifier.

## Results and limitations

- Verifier: exit 0 (checks listed in the tool source).
- Unit tests: 9/9 pass, tamper controls run first.
- `make verify`: exit 0 (559 evidence-packet manifests,
  7161 entries = base 7154 + this packet's 7).
- `make catalogue-check`: exit 2, pre-existing `Stale
  catalogue: README.md` on the new base — not a packet
  regression, and not claimed as passing.
- Full `make test`: NOT attempted; no full-suite tally is
  claimed.
- Unknown: callee internals, runtime `.bss` values, the
  contents of the created file, and the provenance of the
  0x50(%rsp) slot read at the epilogue.
- Next question: decode the next bin_table_init caller FDE
  0x63bd8c0..0x63be4ce (5 raw candidates); or open the next
  leaf family outside opt children.
