# RE-004: what does node #94 gate with the constant 0x68db8bac710cb?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` used for leads only, no code copied
- Claim status: observation for bytes, tables and path reads; inference where marked; unresolved items are listed
- Scope included and excluded: included are all 31 `.text` copies of `0x68db8bac710cb` and `0x68db8bac710cc`, the one
  `.rodata` copy, the 3 uses of the message `could not convert perp usdc to spot`, and a full read of the 15 sites in
  11 functions that no other work item names. Excluded are 13 sites in 13 functions named by other work items, and 3
  sites in 3 functions not read here (`excluded-sites.tsv`). What each function does with the result is not read.

## Reproduce

Run from the repository root. Python 3 standard library only; no objdump, no execution of the binary.

```sh
python3 tools/perp_spot_scale_gate.py --out research/work-items/RE-004-perp-spot-scale-gate-94
python3 -m unittest tests.test_perp_spot_scale_gate
```

The tool checks the binary digest first and takes about 15 s, most of it on the negative controls. FDE extents come
from `tools/fde_extents.py` and sections from `tools/elf_index.py`, so `.bss` and other NOBITS sections are not
address-resolved. Files: `evidence.json`, `sites.tsv`, `excluded-sites.tsv`, `message-sites.tsv`,
`mutation-controls.tsv`.

## Evidence

Addresses are ELF virtual addresses of node #94. All numbers below are in `evidence.json` or the TSV files. The
excerpts are objdump text for reading only and no generated file holds them.

### Census

- `0x68db8bac710cb` is `floor((2^64-1) / 10000)`. The ELF file holds 23 little-endian copies of it and 9 of the next
  integer `0x68db8bac710cc`. The copies inside sections equal the copies in the whole file.
- 31 copies are in `.text`: 22 and 9. Each is the immediate of a REX.W `movabs`, so no 32-bit form can hide another use.
- The remaining copy is at `0x7c6208` in `.rodata`. It belongs to a run of 24-byte records whose first u64 steps through
  `floor((2^64-1) / 10^k)` for k = 2, 4, 6, 8, from `0x7c61f0`. Its readers are not followed.

### Two meanings of one constant

| Class | Sites read | Read | Holds for |
| --- | --- | --- | --- |
| `divisible-by-10000` | 8 | `(y * 0xd288ce703afb7e91) ror 4 <= cap`, the same as `y % 10000 == 0` | all u64 y |
| `branch` | 4 | `x <= cap` reaches `x * 100`, the other edge leaves that path | all u64 x |
| `cmov-zero` | 3 | `x <= cap ? x * 100 : 0` | all u64 x |

Every compare pairs the constants the same way: `cap` with `ja` or `jbe`, and `cap + 1` with `jb` or `jae`. Any other
pair stops the tool, so all rows mean `x <= cap` or its negation.

**The `x * 100` gate.** `scale_lemma` shows that `x <= cap` is exact for `10000 * x` fitting u64 (`cap * 10000` fits and
`(cap + 1) * 10000` does not), and for `100 * x <= floor((2^64-1) / 100)`. So a value that passes the gate can be
multiplied by 100 twice. The rows multiply it once.

**The divisibility test.** `divisibility_lemma` is a proof over all u64, not a sample. `0xd288ce703afb7e91` is the
inverse of 625 mod 2^64, and 10000 is `625 << 4`. Multiplying by an odd constant and rotating are both bijections of
u64. A multiple `10000q` maps to `16q` and then to `q`, which is below `cap + 1`. There are exactly `cap + 1` multiples
in u64 and `cap + 1` values below `cap + 1`, so no other input can land there.

### Sites

`sites.tsv` has one row per site. Its column `scale_or_divisible_edge` gives the rows of `x * 100` for a branch site
and the divisible edge for a divisibility site.

The zero gate at `0x271e0ee`, with copies at `0x4d1ff2e` and `0x4d2067e`:

```
 271e0dc:  call   *0x30557ce(%rip)        # 57738b0
 271e0e2:  xor    %ecx,%ecx
 271e0e4:  test   $0x1,%al
 271e0e6:  cmove  %rcx,%rdx
 271e0ea:  imul   $0x64,%rdx,%r13
 271e0ee:  movabs $0x68db8bac710cb,%rax
 271e0f8:  cmp    %rax,%rdx
 271e0fb:  cmova  %rcx,%r13
```

The input is `rdx` when bit 0 of `al` is set and 0 otherwise, which is why the `input` column of those rows shows a
selection.

The branch gate with tag `0x69` at `0x24f8a4e`, with copies at `0x4ae179e` and `0x4ae1c4e`:

```
 24f8a4e:  movabs $0x68db8bac710cc,%rax
 24f8a58:  movw   $0x69,0x28(%rsp)
 24f8a5f:  cmp    %rax,%rbp
 24f8a62:  jae    24f8ae0
```

Above the cap the edge writes tag `0x69` to the result, and the Display arm of that tag prints `Invalid order`. Below
the cap the walk reaches `imul $0x64,%rbp,%rcx` at two rows, for example `0x24f8b23`.

The fourth branch gate, `0x4d04826`, is in a loop over tokens. Below the cap `x * 100` is computed once before the loop,
at `0x4d048a5`. Above it a second copy of the token lookup runs once, for the first token, without the product. The first
tag on its paths is one of `0xea` `Invalid token`, `0xfb` `Native token does not exist`, `0x160` `Price missing` or
`0x13f` `Invalid input number`. The token checks keep their errors, and a token that passes them gets `0x13f` at
`0x4d04cef`.

The 8 divisibility sites read `[rdi+0x28]` in `0x220bed0`, `0x42e73d0` and `0x42e7980`, two sites each, and a value in
`0x4677fd0`. In the first three functions the divisible edge reaches the label `periodic`, and at one of the two sites
of each function it can also reach `freeze`:

```
 220bf2a:  movabs $0xd288ce703afb7e91,%rax
 220bf34:  imul   %r14,%rax
 220bf38:  ror    $0x4,%rax
 220bf3c:  movabs $0x68db8bac710cc,%rcx
 220bf46:  cmp    %rcx,%rax
 220bf49:  jae    220c148
 220bf4f:  jmp    220bf6c
```

`periodic_prefixes` in `evidence.json` lists the rows from each function entry to the `periodic` lea (35, 34 and 34).
None of them compares a value with 0, and no later row branches into them. So an input of 0 takes the divisible edge.

### The message that names the conversion

The binary holds `could not convert perp usdc to spot` twice, at `0x3eff7e` and `0x71537f`. It has 3 lea sites, and
`message-sites.tsv` shows that each follows a store of tag `0xdf`, that exactly one conditional branch reaches that
block, and that this branch follows a load of the cap. The 3 functions are among the 13 excluded ones, so only these
rows are taken from them and nothing else in them is read.

### How the reads work

Registers and memory start as free values, so nothing is sampled. The tool runs the block that holds the `movabs`, finds
the compare with the constant, and classifies the next row. For a branch it walks both edges through the real bytes:
a call clobbers the caller-saved registers, both sides of every undecided branch are followed, and a visited pair of
address and holder set is not walked again, so loops end. A row of `imul reg,<location>,100` only counts when that
location holds the gated value on the path.

### Negative controls

`mutation-controls.tsv` damages each of the 15 sites in a copy of the bytes, one change at a time. The tool stops if a
change leaves the read unchanged.

| Control | Caught | Survived |
| --- | --- | --- |
| gate condition inverted | 15 | 0 |
| constant low byte changed | 15 | 0 |
| factor 100 changed to 101 | 10 | 0 |
| rotate count changed | 8 | 0 |
| zero cmov source register changed | 3 | 0 |

### Inferences

- `x * 100` is a unit change from perp USDC to spot USDC. The message says so at 3 gates of the same shape, and the
  reference scales fit: `NTL_SCALE` is 1e6 and `QUOTE_WEI_SCALE` is 1e8. The binary has no type name here.
- The cap is written for 10000 because the scaled value must itself stay at most `floor((2^64-1) / 100)`. This is the
  arithmetic of `scale_lemma`. The reason is inferred.
- The input of the `periodic` test is a block height. That comes from the label and the reference names, and this packet
  does not trace the field.

### Reference comparison

- `MAX_SAFE_TIMES_10_000_RAW` in `l1/qtys/impl_ntl.rs` has this value but no user in the reference tree. The name fits
  `10000 * x` fitting u64. The binary uses the value before a multiply by 100, and as the bound of a divisibility test.
- The reference has no `could not convert perp usdc to spot` and no conversion that multiplies by 100 under this cap.
- `l1/abci/engine.rs` has `height != 0 && height % 10_000 == 0` in `periodic_snapshot_due`. The 3 functions read here
  show the remainder test and no test against 0 before the label.

## Implementation and comparison

not yet implemented

## Results and limitations

No progress gate is requested. Metrics, denominator 31 `.text` sites: 15 read, 13 excluded, 3 not read. The 16 unread
sites have an exact address and no claimed meaning.

Limits:

- Different symbolic addresses are treated as different memory, and a stack slot is assumed to survive a call. A callee
  that writes a slot through a pointer would break a read of that slot. Only one branch site, `0x4d04826`, keeps its
  input in a slot.
- A call is modelled from the SysV convention, and its body is not followed.
- A branch site proves that some path below the cap reaches `x * 100`, not that every path does. Paths end at an opcode
  the walker does not model, such as `div`, and at a `ret` or `ud2`. The walk stops after 6000 visited rows.
- The tag column records the first 16-bit constant stored on each path, so it does not prove the tag is the final
  result. At `0x4d04826` it gives 4 tags, and which token data selects each of them is not modelled.
- The block prefix starts at the nearest direct branch target in the same FDE. A jump table entering the block is not seen.
- `0x4677fd0` reaches no known label from its 2 divisibility sites, so what it does with a multiple of 10000 is unknown.
- `tools/fde_extents.py` gives function extents. A linear sweep can resynchronise after a misaligned start, so stopping
  on the FDE end does not prove alignment by itself. Every site was found as an instruction start.

Next question: which value does the slot `0x57738b0` return to the zero gate at `0x271e0ee`, and why does an amount above
the cap become 0 there instead of an error?
