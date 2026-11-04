# RE-001-node115-lu-descbuild: the descriptor builder behind the size-class tables

- Component ID: RE-001-node115-lu-descbuild
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte claims; inference for the
  counter derivations (labelled as arithmetic simulation of the
  disassembled branch structure, not execution); unresolved for the
  header-word semantics and the second caller's purpose.
- Scope included and excluded: included — the `0x63da080` thunk
  FDE, the `0x63d9ba0..0x63d9ed3` body FDE, the `.rodata`
  constants it reads, and the caller FDE's argument setup (cited
  by address only). Excluded — the caller FDE's post-fill
  sequence, the second body caller's internals, the table-fill
  helper itself (packet #228), and all `.bss` table contents
  (runtime-filled, not in the file).

## Reproduce

Working directory: a worktree of upstream main `8fd8db6`.
No execution of the node binary at any point; all commands below
are static reads.

- `objdump -d --start-address=0x63da080 --stop-address=0x63da089
  artifacts/node/115/hl-node` (thunk, 2 instructions).
- `objdump -d --start-address=0x63d9ba0 --stop-address=0x63d9ed3
  artifacts/node/115/hl-node` (body, 819 bytes, single `ret`).
- `python3 tools/fde_extents.py --release 115` (unwind FDE
  extents: thunk `0x63da080..0x63da089`, body
  `0x63d9ba0..0x63d9ed3`).
- `readelf --debug-dump=frames artifacts/node/115/hl-node`
  (unwind range strings, checked by the verifier).
- `python3 tools/node115_lu_descbuild.py` (static verifier,
  exit 0).
- `python3 -m unittest tests.test_node115_lu_descbuild`
  (10/10).
- `make verify` (exit 0), `make catalogue-check` (exit 0),
  `make test` (77 files, 1 pre-existing catalogue Errno 18
  failure, own file [36/77] 10/10).

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000;
`.rodata` file offset = VA (all four constants below are in
`.rodata`, so their file values are quoted directly).

Entry and thunk. `0x63da080`: `endbr64` then
`e9 17 fb ff ff` (`jmp 0x63d9ba0`). The body starts with
`endbr64` at `0x63d9ba0`, pushes six callee-saved registers,
and ends with a single `ret` at `0x63d9ed2`. The body contains
zero `call` mnemonics (objdump mnemonic count); the two raw
`0xe8` bytes inside the body are instruction immediates, not
opcodes (verified by disassembly, as in packet #225).

Constants (`.rodata`, little-endian). `[0x4595a0]` qword =
`0x100000003` (stored to descriptor `+0x70`, giving sub-block 1
`shift1 = 3`, `value = 1`). `[0x451510]` = dwords `[1, 3, 1, 3]`
(qword `0x300000001` stored to `+0x7c`; full 16 bytes stored to
`+0x60`, giving sub-block 1 `shift2 = 3` and sub-block 0's
`+0x18` tail `= 1`). `[0x452980]` = dwords `[0, 3, 3, 0]`
(stored to `+0x4c`, giving sub-block 0 `shift2 = 3`,
`shift1 = 3`, `value = 0`, and header `+0x4c..+0x4f = 0`).
`[0x96dc38]` u16 = `0x0100`, so every flag byte it writes is
`0x00` (low byte) with `0x01` in the following unread byte.

Record shift. The builder's first-loop pointer starts at
`rdi + 0x84` and the main loop's pointer at
`rdi + n * 0x1c` with stores at `+0x4c`, while packet #228's
reader grid starts at `+0x50`. Each record's first dword
therefore lands in the previous sub-block's `+0x18` tail and
equals the next index; the reader's fields come from record
bytes `+0x04..+0x10`. This is visible directly in the
disassembly (e.g. first-loop store `[r9] = r10d` at `+0x84`
with the sub-block's `shift2 = 4` stored at `[r9+0x04] =
+0x88`).

First loop. `r10 = 2, 3, 4`; divisor `r10 * 16`; the inner
division loop exits at the smallest multiple of `0x1000`
divisible by the divisor; stored pages are `1, 3, 1`
(`lcm(0x1000, 32)/0x1000 = 1`, `lcm(0x1000, 48)/0x1000 = 3`,
`lcm(0x1000, 64)/0x1000 = 1`).

Main loop. Outer `esi = 6..62` (compare against `0x3e` for
the setne that selects inner count 4 vs 3; final exit when
next-`esi == 0x3f`); inner `r8 = 1..4` (`1..3` for `esi == 62`);
running counter `r11d` starts at 5 and ends at 232.
Per-iteration `s = (r8 + 1) << (esi - 2)`; flag =
`(s & 0xfff) == 0` (`sete` after `and $0xfff`); small path
(`s <= 0x1000`) vs big path (`s <= 0x3fff` keeps the division
result, `s > 0x3fff` zeroes it); counted path (`s <= 0x3fff`)
updates the `[rsp-0x2c]` counter, `[rsp-0x18]` next-`esi`,
and `[rsp-0x28]` last `s`.

Final header. `bsr(232) = 7`; the `and` with 231 yields 224
but only its carry (0) feeds the `sbb`, so the stored third
word is the un-ANDed 232 and the fourth is `7 + 1 = 8`.
`[record+0x40]` is the final iteration's `s`
(`esi = 62, r8 = 3`: `4 << 60 = 2^62`). All header values
were reproduced by an arithmetic simulation of the branch
structure in the verifier (pure integer arithmetic over the
decoded loop bounds, not binary execution).

Callers (per-site disassembly confirmed). Thunk: `0x634ed44`
in FDE `0x634ece0..0x634f09d` (descriptor at `rsp+0xf0`,
zeroed with `rep stos` over `0x336` qwords, then the thunk
call, then the table-fill call with the same base and a byte
from `.data 0x64ffb5c`). Body: `0x634c2a5` in FDE
`0x6349be0..0x634eb7c` (`rdi = [rsp+0x30]`), plus the thunk
jump at `0x63da084`. No `.rela.dyn` addend equals either
address (60,723 entries checked).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed
for this helper. The verifier independently re-derives the
exhibit bytes, strict counts, key opcodes, census, and the
header counter values from the file; it does not execute the
binary. Boundary cases checked: sub-block 0 (first), sub-block
33 (last small-path), sub-block 231 (last, `s = 2^62`),
and the `esi == 62` short inner loop (3 iterations).

## Results and limitations

Machine-readable metrics: 5 excerpts, 429 bytes, 98 strict
mnemonics; thunk 9 bytes / 2 strict; body 819 bytes / 1 ret /
0 calls; census thunk 1 E8, body 1 E8 + 1 E9, 0 GOT both;
MANIFEST 15/15. What remains unknown: the semantic identity
of the header words beyond their counter derivations, the
second body caller's purpose, the consumers of the unread
sub-block tails, the reason for the 4-byte record shift, and
what `2^62` represents in the allocator's address space.
Next question: decode the FDE starting at `0x63d9340` (packet
#227's fourth size-helper caller: class-index derivation and
the bitmap-bit clear at record `+0x400`).
