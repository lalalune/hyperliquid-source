# RE-004: what does node #94 do when an Sz add or subtract overflows?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` used for leads only, no code copied
- Claim status: observation for bytes, tables and path proofs; inference where marked; unresolved items are listed
- Scope included and excluded: included are the 74 lea sites of the two `l1/src/qtys/impl_sz.rs` Locations, and for
  the 35 sites in 24 functions no other work item names, every conditional edge into the site, the saturated value
  and the join with the non-overflow path. Excluded are the 39 sites in 16 functions named by other work items
  (`excluded-functions.tsv`), and what each function does with the result after the join.

## Reproduce

Run from the repository root. Python 3 standard library only; no objdump, no execution of the binary.

```sh
python3 tools/sz_saturating_sites.py --out research/work-items/RE-004-sz-saturating-sites-94
python3 -m unittest tests.test_sz_saturating_sites
```

The tool checks the binary digest first and takes about 60 s, nearly all of it on the negative controls. FDE extents
come from `tools/fde_extents.py` and sections from `tools/elf_index.py`, so `.bss` and other NOBITS sections are not
address-resolved. Files: `evidence.json`, `sz-sites.tsv`, `excluded-functions.tsv`, `mutation-controls.tsv`.

## Evidence

Addresses are ELF virtual addresses of node #94. All numbers below are in `evidence.json`.

### Census

- 11 Location records have a path ending in `l1/src/qtys/impl_sz.rs`: 7 with line 9 column 1 and 4 with line 35
  column 1. No other line appears, and no relocation points at any of the records.
- Those records have 74 rip-relative lea sites: 49 for line 9 and 25 for line 35. All are instruction starts of their
  FDE (linear sweep from the FDE start, which has to end exactly on the FDE end). They fall in 40 FDEs.
- Every analysed site passes the record in `rsi` and 0 in `dil` to the slot `0x5773190`, whose RELATIVE relocation
  holds `0x358dcd0`. That function starts an FDE and has 2 `ret` rows.

### Results at the 41 guards of the 35 analysed sites

The site table has one row per conditional edge into a site.

| Operation | Line | Guards | Condition | Value on the overflow edge | Compiled form |
| --- | --- | --- | --- | --- | --- |
| unsigned add | 9 | 9 | carry, or sign of x for x + x | `u64::MAX` | constant |
| unsigned sub | 9 | 8 | borrow | 0 | constant |
| signed add | 35 | 12 | signed overflow | `(L >>s 63) ^ i64::MIN` | `sar`, `xor` |
| signed sub | 35 | 12 | signed overflow | `i64::MAX + (L >= 0)` | `setns`, `add` |

L is the wrapped result. On the other edge the same location holds L. No site in the two lines has any other shape:
a guard that does not test the expected flag stops the tool.

`saturation_lemma` checks that both signed forms equal the saturated value whenever the signed operation overflowed.
It runs all 65536 pairs at 8 bits and 49 edge pairs at 64 bits. The general argument is short: a true result above
`i64::MAX` wraps negative, and one below `i64::MIN` wraps non-negative, and both forms read only that sign.

### Shapes worth reading

Saturate, then record, then rejoin (`0x23971ae`, signed sub):

```
2397193  sub    r12,r13
2397196  jno    2397130
2397198  setns  al
239719b  movzx  eax,al
239719e  movabs rcx,0x7fffffffffffffff
23971a8  add    rcx,rax
23971ab  sub    rbp,r13
23971ae  lea    rsi,[rip+0x330be13]        # 56a2fc8
23971b5  cmovo  rbp,rcx
23971b9  xor    edi,edi
23971bb  call   QWORD PTR [rip+0x33dbfcf]  # 5773190
23971c1  mov    r12,rbp
23971c4  jmp    2397130
```

Record, then recompute and saturate (`0x36f65c9`, unsigned add):

```
36f65c7  xor    edi,edi
36f65c9  lea    rsi,[rip+0x1ffb930]        # 56f1f00
36f65d0  call   QWORD PTR [rip+0x207cbba]  # 5773190
36f65d6  add    rbp,r13
36f65d9  mov    rax,0xffffffffffffffff
36f65e0  cmovb  rbp,rax
```

Doubling, guarded by the sign bit, 7 guards in 4 functions (`0x370e35e`):

```
370e35b  test   rbx,rbx
370e35e  js     370e51e
370e364  lea    rdx,[rbx+rbx*1]
```

The sign bit of x is the carry out of x + x, so the tool treats this guard as an add with both operands equal. The
cold block calls the recorder and goes on with `u64::MAX` in the result register.

`evidence.json` counts 30 of 41 guards holding the saturated value before the recorder call, and 11 computing it
after. The order changes no result on either path.

Operands are often not plain registers. `sz-sites.tsv` shows forms such as `|a| + |b|` at `0x36f65c9`, x - |y| at
`0x3712026`, a value negated by a flag byte at `0x3712be2` and `0x3714d47`, and 0 - x at `0x23971ae`.

### How the proof works

Registers and memory start as free values. A value is a sum of atoms with coefficients mod 2^64, and any other pure
operation is one atom of its inputs, so equal inputs give an equal atom. Flags stay as the operation and operands that
set them. Taking a branch adds its condition to the path, so a later `cmovo` or `cmovb` on the same operands is settled
by that branch. Nothing is sampled, and each guard holds for all 2^128 operand pairs on its two paths.

For each guard the tool runs the block that ends in the branch, then walks both edges through the real bytes. The
overflow edge must reach the recorder once with the right Location. The two paths must then reach a common address
where some register or memory location holds the saturated value on one side and L on the other. A different address
of the Location, a wrong kind, or a guard that enters the site when no overflow happened all stop the tool.

### Negative controls

Each of the 35 sites is damaged in a copy of the bytes, one change at a time, and analysed again (`mutation-controls.tsv`).

| Control | Caught | Survived |
| --- | --- | --- |
| recorder call replaced by a nop | 35 | 0 |
| guard condition inverted | 41 | 0 |
| cmov or setcc condition inverted | 27 | 0 |
| shift count changed | 11 | 0 |
| `xor r,r` changed to `or r,r` | 5 | 0 |
| add and sub swapped in the cold block | 27 | 4 |
| immediate changed in the cold block | 31 | 5 |

All 9 survivors write no location that holds the result, and the tool stops if a survivor ever does. Five are constants
rebuilt after the call (`0x7ffffffffffffffe` four times, and `0x346dc5d63886594b` at `0x3714d7a`). Four are
the arithmetic of the next operation after the site, for example `add r13,r12` at `0x36f65ea`.

### Inferences

- Line 9 is `Sz` and line 35 is the signed `Szi`: from the file name, the widths and the reference names. The binary
  carries no type name here.
- The recorder returns: the overflow paths go on past the call, and its FDE has `ret` rows. This packet does not read
  what it stores.
- The doubling is `x + x` on `Sz`, not a multiply by 2, because it records through the same Location as the adds.

### Reference comparison

The reference comments and `add_recording_overflow`, `sub_recording_underflow` and `sub_recording_overflow` in
`l1/qtys/impl_sz.rs` match the binary at the analysed sites: `u64::MAX`, 0, and the signed saturation. The reference
always records first, while the binary holds the value first at 30 of 41 guards. That is compiled order and does not
change a result. The reference has no doubling helper.

## Implementation and comparison

not yet implemented

## Results and limitations

No progress gate is requested. Metrics, denominator 74 lea sites: 35 sites analysed and proved at 41 guards, 39 sites
not analysed. Some of the 16 excluded functions appear in other packets only as callers. They are left out anyway, so
this packet shares no function address with another work item.

Limits:

- Different symbolic addresses are treated as different memory, so two pointers that alias would break a proof. Stack
  slots are keyed by their `rsp` offset.
- Accesses of different sizes to one slot are not modelled as overlapping: such a read gives a fresh value, which
  can only fail the proof.
- The block prefix starts at the nearest direct branch target in the same FDE. A jump table or another FDE entering
  the block is not seen.
- The recorder is modelled from its calling convention: it clobbers the SysV caller-saved registers and all flags. Its
  body is not followed. Each overflow path is checked at its first join, and later uses of the result are not.
- A linear sweep can resynchronise after a misaligned start, so stopping on the FDE end does not prove alignment by
  itself. Every lea was found as an instruction start.
- A branch on any other condition forks the walk and both sides are followed. Paths stop at 70 steps, 24 forks, any
  other call, or an opcode the walker does not model. A path that stops before a join fails the proof.
- The 39 excluded sites are unanalysed; their count is exact, their semantics are not claimed.

Next question: what do `0x370e2a0` and `0x3710a70` compute with 2x? They double two sizes next to a 128-bit `mul`, a
division and the constant `0x7ffffffffffffffe`, and `0x370ea50` and `0x370ee20` hold the same guards.
