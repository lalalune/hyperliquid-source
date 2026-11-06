# RE-001-node115-lu-bintableinit-caller-5sites-walk: bounded question

- Component ID: lu bin_table_init caller, five-variant lookup walk
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit:
  05bc2de303c05525b71e7e257426e741bc66a390 (upstream main, fetched
  and confirmed unmoved at build start and at final rev-parse)
- Claim status: observation for all addresses, counts, and branch
  shapes below; inference for the move-to-front reading of the
  0x100-array swap and for the "five variants of one walk" framing;
  unresolved: whether the five variants are five distinct callers
  or one caller inlined five times, and all runtime `.bss` values.
- Scope included and excluded: included: FDE 0x63bd8c0..0x63be4ce
  only (3086 bytes, 661 strict lines, 23 calls, 1 ret), its five
  bin_table_init sites, its five lu-miss sites, its 8-slot scan,
  and its size-class blocks. Excluded: bin_table_init itself
  (0x63d9880..0x63d9a64, #262), the lu-miss handler
  (0x63d9700..0x63d987b, #215), the previous FDE walk helper
  (0x63bd6c0..0x63bd8b5), all other callee internals, and the
  remaining 107 static leaves.

## Reproduce

Working directory: the worktree root. Tool: system objdump
(`objdump -d --start-address=0x63bd8c0 --stop-address=0x63be4ce
artifacts/node/115/hl-node`). The objdump exhibit is the verbatim
output of that command. The `.hex` exhibit is the raw binary slice
at `.text` file offset VA - 0x1000, length 3086. No execution, no
side effects; the verifier and tests read bytes only. `make verify`
and `make catalogue-check` were run in the worktree; full
`make test` was NOT attempted (584 files on the new base).

## Evidence

Original addresses in VA; `.text` file offset = VA - 0x1000.
FDE bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte
range fields): previous FDE 0x63bd6c0..0x63bd8b5, this FDE
0x63bd8c0..0x63be4ce, next FDE 0x63be4d0..0x63be53d. Gap before
11 bytes of 0xcc; padding after 2 bytes of 0xcc. Entry bytes
f3 0f 1e fa (endbr64). Frame 0x1b8; canary at 0x1a8(%rsp),
checked at 0x63bdaa7, `__stack_chk_fail` call at 0x63be258;
single ret at 0x63bdad2 (byte 0xc3).

Call census from the objdump exhibit (mnemonic lines only):
23 calls total = 5 bin_table_init (0x63bdbcd, 0x63bdea5,
0x63bdf68, 0x63be099, 0x63be24a; all rdi = lea 0x20(%rsp)) +
5 lu-miss (0x63be1ee, 0x63be362, 0x63be44e, 0x63be487,
0x63be4c0; all rdi = r15, rsi = lea 0x6511a00, rcx = r12,
r8 = 1, r9 = 0, rdx = rbx/rbx/r13/rbp/rbp) + 13 other sites
(0x63bd2e0, 0x63bcd20, 0x63b7240, 0x63b73a0, memcpy@plt,
0x63b7500, 0x63bd6c0, 0x63637f0, 0x63ead50, 0x6363260 x2,
0x63eb870, `__stack_chk_fail`@plt).

Null-context branch shape, verified per site: entry site block
0x63bdbc0 is the target of `je` at 0x63bd91c, preceded by
`test %rdi,%rdi`; variant blocks 0x63bde98, 0x63bdf5c,
0x63be08d, 0x63be23e are targets of `je` at 0x63bdae2,
0x63bdcda, 0x63bddb3, 0x63bdc67 respectively, each preceded by
`test %r15,%r15`. Each site's rejoin resumes its walk variant
(0x63bd922, 0x63bdae8, 0x63bdce0, 0x63bddb9, 0x63bdc6d).

Walk skeleton, repeated in each variant: (key >> 0x1a) & 0xf0
top index into context + 0x1b0; high-bits compare against
key & 0xffffffffc0000000; second level (key >> 0x9) &
0x1ffff8 + table + 0x8. Size-class blocks at 0x63bde21 and
0x63bdf9a: bsr, clamp 6..7, index -0x17 + 4 * class + low
2 bits, 0x23 threshold byte from 0x67277c0, thresholds 0x1000
and 0x7000000000000000. Scan array at context + 0x100,
16-byte entries, slots 1..7 compared, slot 0 as MRU head.

`.rela.dyn` census: 60,723 entries total, 59,534 RELATIVE
(R_X86_64_RELATIVE, type 8), stated distinctly. Raw-e8 census
for target 0x63d9880 grouped by enclosing `.eh_frame` FDE:
10 / 8 / 6 / 6 / 5 (this FDE) / 4 (eight FDEs). Analysis is
complete for the stated window; no timeout, no truncation.

## Implementation and comparison

No implementation is claimed. The packet ships a static
verifier (byte reads only) and unit tests with tamper controls
(hex flip, strict-count change, call-site change, injected
overlap — each confirmed to fail the verifier) plus a clean
temp-copy pass and regeneration comparisons (objdump output
and binary slice). Not yet implemented/measured: any Rust
reconstruction of this walk, and any runtime confirmation of
the `.bss` gate byte or table contents.

## Results and limitations

Machine-readable metrics with denominators: strict 661/661
recount match; calls 23/23; bin_table_init sites 5/5;
lu-miss sites 5/5; ret 1/1; `.rela.dyn` 60,723 total /
59,534 RELATIVE; disjointness: 0 overlaps over the merged
tree plus prior worktree records (37,404 ranges scanned
independently). `make verify` exit 0; `make catalogue-check`
exit 2, pre-existing `Stale catalogue: README.md` on the new
base, not a packet regression. Full `make test` not run
(declared, not claimed). Remaining unknown: the five-variant
provenance question above, and the next caller FDE.

Next question: decode the next bin_table_init caller FDE
0x63cb150..0x63cba04 (4 raw candidates, 2228 bytes).
