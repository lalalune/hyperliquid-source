# RE-001: lu bin_table_init 1-site scan bsr caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-scan-bsr
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly census, byte comparison, FDE
  bounds); helper-body semantics are cited, not claimed
- Scope included and excluded: FDE `0x6362f90..0x6363258` only. The
  bin_table_init body, the lu-miss handler, the tail-jump target
  FDE, and all tables are cited or read, not claimed. Neighboring
  FDEs are not decoded here.

## Reproduce

Static analysis only; the node binary is never executed. In the worktree
root, with `objdump` (binutils) and `readelf`:

- `objdump -d --start-address=0x6362f90 --stop-address=0x6363258
  artifacts/node/115/hl-node` reproduces the objdump exhibit
  (152 strict mnemonic lines).
- `readelf -r -W artifacts/node/115/hl-node` reproduces the relocation
  census (`.rela.dyn` 60,723 total / 59,534 RELATIVE, `.rela.plt` 278).
- `python3 tools/node115_lu_bintableinit_caller_scan_bsr_1site.py`
  runs the static verifier (byte reads only).
- `python3 tests/test_node115_lu_bintableinit_caller_scan_bsr_1site.py`
  runs the unit tests (tamper controls first, then the clean temp-copy
  verifier run).

## Evidence

Original addresses are virtual addresses (VA); `.text` file offset is
VA − 0x1000, `.rodata` is VA as-is, `.data` is VA − 0x3000. FDE bounds
come from an own `.eh_frame` parse (PC-relative sdata4 encoding,
fixed 4-byte range fields, CIE pointer relative to the CIE_id field;
three CIEs, two zPLR; the `L` augmentation entry is an encoding byte
only with no value; FDE list sorted before bisect; 135,313 FDEs
total, reproduced). Previous FDE `0x6362910..0x6362f82` (gap 14 bytes,
all `0xcc`); next FDE `0x6363260..0x6363552` (padding 8 bytes, all
`0xcc`).

Window census (from the objdump exhibit, never copied from a prior
packet): 152 strict lines, 3 calls, 0 ret, 1 bin_table_init site
(`0x6363095`, `lea 0x10(%rsp)` in-block via `r13`), 1 lu-miss site
(`0x6363249`), 1 bsr (`0x6363110`), 0 lock sub, 0 lock add, 21 jump
instructions, the sole outside-window target being the tail jump at
`0x636307f` to `0x63aefe0`. Raw `0xe8` census (byte scan for `e8`
with rel32 target `0x63d9880`, grouped by enclosing `.eh_frame`
FDE): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this
FDE holds 1 raw site, matching its 1 objdump site.

Size class: `cmp $0x1000,%rbp` at `0x6363013`, `ja 0x63630f0`
(bsr block). Below the gate, threshold table `0x67277c0` is indexed
by `(rbp + 7) >> 3` at `0x6363020..0x636302f`; the size-class byte
in `r11` is shifted left by `0x14` into `r10`, or-ed with `(%rdx)`
masked by `$0xfffffffff00fffff`, and stored back at `0x6363048`.
The bsr block at `0x63630f0` guards against overflow with
`movabs $0x7000000000000000,%rcx` (`jb 0x6363150` on overflow,
which sets `r10d = 0xe800000`, `r11d = 0xe8`); otherwise
`rax = 2*rbp - 1`, `bsr %rax,%r8` at `0x6363110`, the shift count
clamped to a minimum of 7 then minus 3, and the rounded size
rejoins the size-class computation at `0x636303b`.

Phase-1 walk on the context+`0x1b0` table (`lea 0x1b0(%rdi),%r13`
at `0x6362f96`): top index `(key >> 0x1a) & 0xf0`, high bits
`key & 0xffffffffc0000000`, second level
`(key >> 0x9) & 0x1ffff8 + table + 0x8`. On a top-level match the
second-level value is shifted (`shl/sar $0x10`) and masked
(`$0xffffffffffffff80`) at `0x6363007..0x636300f`, then written
back into its slot at `0x6363048` — no `0x6727a00` table read
happens in this FDE, unlike the #288–#297 walkers. A top-level
mismatch falls to the scan at `0x63630a8`.

Null-context site: `test %rdi,%rdi; je 0x6363088` at
`0x6362fc1..0x6362fc4` leads to block `0x6363088`
(`lea 0x10(%rsp),%r13; mov %rsi,0x8(%rsp); mov %r13,%rdi`),
call at `0x6363095` (`e8 e6 67 07 00` -> `0x63d9880`),
rejoin `mov 0x8(%rsp),%rsi; jmp 0x6362fca`. No other jump in the
window targets `0x6363088`; the preceding instruction is `nopl`
padding at `0x6363084`.

Scan (8 slots, table+`0x100` in `r13`, move-to-front on a hit):
slot 0 at `0x63630a8` (`cmp 0x100(%r13),%rcx`), slot 1 at
`0x636316e` (`cmp 0x110(%r13),%rcx`), slots 2..7 unrolled at
`0x63631c6..0x6363228` (slot 2 `cmp 0x120(%r13),%rcx`, slot 3
reversed-operand `cmp %rcx,0x130(%r13)`, slot 4
`cmp 0x140(%r13),%rcx`, slot 5 reversed-operand
`cmp %rcx,0x150(%r13)`, slot 6 `cmp 0x160(%r13),%rcx`, slot 7
`cmp 0x170(%r13),%rcx`). Slot-0 hit uses the inline head-swap
block at `0x63630b5..0x63630e3`, then `jmp 0x6363004`; other hits
use the move-to-front block at `0x6363177` (`r8d` = slot index,
shift `*16`, swap slot into head), then `jmp 0x63630ce`.
Exhaustion falls to the lu-miss call at `0x6363249`
(`rdi` = context, `rsi` = `lea 0x6511a00`, `rdx` = scan table,
`rcx` = key, `r8` = 1, `r9` = 0), rejoining at `0x6363004`.

Exit (0 ret, 1 tail jump): the shared epilogue at `0x6363062`
(`add $0x1a8,%rsp` + pops, after the canary check at
`0x636304b..0x636305c`) sets `rdi` = context, `r8d` = 0,
`ecx` = size class, `rsi` = `lea 0x6511a00`, and jumps to
`0x63aefe0` at `0x636307f`. Canary failure goes to `0x6363253`,
which calls `__stack_chk_fail` (`0x63f0d70`).

## 1-raw tier survey

Own `.eh_frame` parse (135,313 FDEs) + raw-e8 census (total 108,
tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17) + per-candidate
objdump census + exhibits-scoped claim check (54,785 priors,
0 skipped). All 17 candidates carry exactly 1 objdump-verified
bin_table_init site. Excluded: `0x63adf40..0x63ae252` (overlaps
packet #214's claimed sub-ranges, listed in records.json).
Survivors in address order: `0x6362f90` (this packet),
`0x6363260`, `0x63637f0`, `0x6363d50`, `0x6387420`, `0x63adb50`,
`0x63ae2b0`, `0x63ae6e0`, `0x63ae980`, `0x63aed40`, `0x63aefe0`,
`0x63af460`, `0x63afc60`, `0x63bc490`, `0x63bc730`, `0x63c2f00`.

## Results and limitations

Machine-readable metrics are in records.json. The verifier and unit
tests are the acceptance gates for this packet; the full `make test`
suite is not run (584 files on the new base; hours of runtime and
VM-restart risk), declared in the README rather than hidden. The
tail-jump target FDE `0x63aefe0..0x63af45f` is a future 1-raw
packet, not decoded here.
