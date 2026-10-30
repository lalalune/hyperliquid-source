# RE-004: which operation does each overflow recorder Location of l1/src/qtys compute in node #94?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` used for leads only, no code copied
- Claim status: observation for bytes, tables and path proofs; inference where marked; unresolved items are listed
- Scope included and excluded: included are all 72 Location records of ten lines, `l1/src/qtys/mod.rs` 827 to 831 and
  `l1/src/qtys/impl_ntl.rs` 6, 16, 26, 62 and 664, their 687 lea sites, and for the 81 functions no other work item
  names, every conditional edge into every recorder call those leas feed. Excluded are the 475 leas in 183 functions
  named by other work items or pending packets (`excluded-functions.tsv`), so `mod.rs:828` and `impl_ntl.rs:6` have no
  read guard. Also excluded are the lines packeted already (`impl_sz.rs` 9 and 35, `impl_wei.rs` 6, `impl_ntl.rs` 665),
  the lines `mod.rs` 843 and 844 and `impl_px.rs` 149, which this packet does not read, and what callers do with a
  result.

## Reproduce

Run from the repository root. Python 3 standard library only; no objdump, no execution of the binary.

```sh
python3 tools/qty_recorder_lines.py --out research/work-items/RE-004-qty-recorder-lines-94
python3 -m unittest tests.test_qty_recorder_lines
```

The tool checks the binary digest first and takes about 20 s here. FDE extents come from `tools/fde_extents.py` and
sections from `tools/elf_index.py`, so `.bss` and other NOBITS sections are not address-resolved. Files:
`evidence.json`, `line-table.tsv`, `sites.tsv`, `cooccurrence.tsv`, `record-neighbours.tsv`, `excluded-functions.tsv`,
`unresolved.tsv`, `mutation-controls.tsv`.

## Evidence

Addresses are ELF virtual addresses of node #94. All numbers below are in the generated files. The disassembly excerpt
below is for reading only and is not part of them.

### Census

- Location records are found through RELATIVE relocations: 72 records hold those ten lines, and all have column 1.
- The records have 687 rip-relative lea sites in 264 FDEs. 212 leas in 81 FDEs are read here.
- The recorder is the slot `0x5773190`, whose RELATIVE relocation holds `0x358dcd0`. That function starts an FDE and has
  `ret` rows.
- The compiler hoists these leas, so a lea is not the site. A forward walk from each lea finds the recorder calls that
  run with that record in `rsi`, through a register copy or a `call` through a register that a `mov` in the same
  function loads from the slot. All 212 read leas reach a call, and each of the 183 bound calls is reached by one record
  only.

### Result: one line, one signedness

`line-table.tsv`. The operation column comes from the flag the guard tests and the value on its overflow edge, never
from the line number, so a mixed line would show up here.

| Line | Records | Leas | Leas read | Guards proved | Add | Sub | Signedness | Value on overflow | Unresolved |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mod.rs:827` | 12 | 71 | 37 | 27 | 27 | 0 | unsigned | `u64::MAX` | 0 |
| `mod.rs:828` | 3 | 11 | 0 | 0 | | | not read | | 0 |
| `mod.rs:829` | 14 | 92 | 43 | 49 | 49 | 0 | unsigned | `u64::MAX` | 1 |
| `mod.rs:830` | 9 | 91 | 21 | 19 | 19 | 0 | signed | `(L >>s 63) ^ i64::MIN` | 1 |
| `mod.rs:831` | 8 | 146 | 54 | 47 | 47 | 0 | unsigned | `u64::MAX` | 0 |
| `impl_ntl.rs:6` | 3 | 4 | 0 | 0 | | | not read | | 0 |
| `impl_ntl.rs:16` | 3 | 7 | 2 | 2 | 0 | 2 | signed | `i64::MAX + (L >= 0)` | 0 |
| `impl_ntl.rs:26` | 4 | 27 | 4 | 4 | 1 | 3 | unsigned | add `u64::MAX`, sub 0 | 0 |
| `impl_ntl.rs:62` | 12 | 140 | 32 | 31 | 2 | 29 | signed | add `sar`/`xor`, sub `setns`/`add` | 2 |
| `impl_ntl.rs:664` | 4 | 98 | 19 | 24 | 24 | 0 | unsigned | `u64::MAX` | 0 |

L is the wrapped result. The 203 proved guards sit at 179 calls. Each proof reads real bytes on both edges with free
registers and memory, so it holds for all operand pairs on those paths and samples no value. On the other edge the same
location holds L. 194 guards compare the two edges at a common address. The other 9 have an overflow path with no common
address inside the walk, and there the location is compared at the end of the overflow path; `sites.tsv` writes `none`
in the `joins` column. 44 guards hold the saturated value before the recorder call and 159 compute it after.

The two signed forms are the ones `saturation_lemma` covers: it checks them against the true saturated value for all
65536 pairs at 8 bits and 49 edge pairs at 64 bits. A true result above `i64::MAX` wraps negative and one below
`i64::MIN` wraps non-negative, and both forms read only that sign.

4 guards of `impl_ntl.rs:664` are `test x,x; js` with `left` equal to `right`: the sign bit of x is the carry of x + x.
`0x26f96aa` doubles `rbp` and `r12` that way when the byte at `+0x110c` of `rbx` is not 0.

### A hoisted site

`0x4d8dc82` holds the Location of `mod.rs:831` before the loop, `0x4d8dc89` loads the recorder into `r12`, and `0x4d8dcd0`
rebuilds `rsi` after the call:

```
4d8dc82: lea    0x99d2c7(%rip),%rsi        # 572af50
4d8dc89: mov    0x9e5500(%rip),%r12        # 5773190
4d8dc90: mov    $0xffffffffffffffff,%r13
4d8dc97: jmp    4d8dcaf
4d8dca0: mov    %rbp,%rdx
4d8dca3: add    $0x48,%r15
4d8dca7: mov    %rdx,%rbp
4d8dcaa: dec    %r14
4d8dcad: je     4d8dcdb
4d8dcaf: cmpq   $0x0,-0x8(%r15)
4d8dcb4: jne    4d8dca0
4d8dcb6: mov    (%r15),%rbx
4d8dcb9: mov    %rbx,%rdx
4d8dcbc: add    %rbp,%rdx
4d8dcbf: jae    4d8dca3
4d8dcc1: xor    %edi,%edi
4d8dcc3: call   *%r12
4d8dcc6: add    %rbp,%rbx
4d8dcc9: cmovb  %r13,%rbx
4d8dccd: mov    %rbx,%rdx
4d8dcd0: lea    0x99d279(%rip),%rsi        # 572af50
4d8dcd7: jmp    4d8dca3
```

The saturation constant is in `r13`, set outside the guard's block. `reaching_constants` is a forward dataflow from the
function entry that keeps a constant only while every path holds it; any instruction that may write the register drops
it, and a function with an indirect jump gets none.

### Line counts against typed partners

`cooccurrence.tsv` counts functions that hold a lea of both lines, over all FDEs, from lea bytes alone.

| Line | Functions | `impl_sz.rs:9` | `impl_sz.rs:35` | `impl_wei.rs:6` | `impl_ntl.rs:62` | `impl_ntl.rs:665` |
| --- | --- | --- | --- | --- | --- | --- |
| `mod.rs:827` | 37 | 10 | 0 | 3 | 0 | 0 |
| `mod.rs:828` | 6 | 1 | 5 | 0 | 3 | 0 |
| `mod.rs:829` | 52 | 2 | 3 | 5 | 6 | 0 |
| `mod.rs:830` | 46 | 2 | 2 | 2 | 22 | 9 |
| `mod.rs:831` | 87 | 0 | 0 | 25 | 1 | 6 |

`record-neighbours.tsv` lists the record 0x18 away from each chosen record. 5 of the 12 `mod.rs:827` records have an
`impl_sz.rs:9` record right after them.

### Inferences (not observed)

- The five `mod.rs` lines are five macro invocations, one per quantity type: all have column 1 and sit on adjacent lines.
- `mod.rs:827` is `Sz`, `mod.rs:828` signed `Szi`, and `mod.rs:831` `Wei`, from the partner counts and from the
  signedness where a guard was read. `mod.rs:828` rests on the counts alone.
- `mod.rs:829` and `mod.rs:830` are the unsigned and signed notional pair, likely `Ntl` and `Ntli`. This is weaker: 830
  pairs with `impl_ntl.rs:62` in 22 of 46 functions, but 829 has no strong partner.
- The `mod.rs` lines do not hold `Add` and `Sub` of those types, because no subtract was read in them and `impl_sz.rs:9`,
  `impl_sz.rs:35` and `impl_wei.rs:6` already hold both. Whether they are `Sum`, `AddAssign` or something else is
  unresolved.

### Reference comparison

The reference is a lead, not a target. `l1/qtys/mod.rs` adds `Ntl` with `saturating_add` and no recorder, and
`l1/qtys/impl_ntl.rs` adds with a plain `+`. It has no `Sum` impl in `l1/qtys`, and it records only for `Sz`, `Szi` and
one `Wei` pair debit. In the binary all 203 proved guards, on eight lines, call the recorder and then go on with a
saturated value.

## Implementation and comparison

not yet implemented

Tool correctness is shown by negative controls. `tests/test_qty_recorder_lines.py` holds 34 tests, and
`mutation-controls.tsv` records one damage per row, restored after each run:

| Control | Stopped | Changed rows | Same |
| --- | --- | --- | --- |
| recorder call removed | 179 | 0 | 0 |
| guard inverted | 203 | 0 | 0 |
| cold `cmov`/`setcc` inverted | 194 | 9 | 0 |
| cold add/sub swapped | 194 | 9 | 12 |
| cold immediate changed | 162 | 0 | 8 |
| shift count changed | 21 | 0 | 0 |
| `xor` to `or` | 17 | 0 | 6 |

Stopped means the guard no longer proves. Changed rows means it proves with a different location, join or operation: at
those 9 calls the result is in two locations, the damage removes one, and the other still proves. The 26 survivors write
no result location, and the tool stops if a survivor ever does.

## Results and limitations

Passed: 203 of 207 guards at 179 of 183 bound calls in the 81 read functions, and all 212 read leas bind. No progress gate
is requested.

Unresolved (`unresolved.tsv`, 4 guards): `0x3958945`, `0x395c317` and `0x3c02bac` end with no location compared, and the
edge from `0x395c2fa` into `0x395c437` tests no overflow flag. Their lines are `impl_ntl.rs:62`, `mod.rs:830`, `mod.rs:829`
and `impl_ntl.rs:62`.

Limits:

- 475 of 687 leas are unread, so the table proves nothing for them, and `mod.rs:828` and `impl_ntl.rs:6` have no row.
  Counts for the lines with few read guards, such as `impl_ntl.rs:16` with 2, say little about the whole line.
- Different symbolic addresses are treated as different memory. The recorder body is modelled from its calling
  convention, and the walk stops at 70 rows per path.
- Binding drops only the registers an unmodelled instruction names, and it marks each address once per set of holders.
- The location check is "some location", so a survivor could in principle hide behind a shadow copy. `guard_rows`
  compares the whole location list to catch that (`test_shadow_copy_does_not_hide_a_changed_result`).
- A linear sweep that ends on the FDE end does not prove alignment at every row.
- Type names in the inferences come from file names and counts, not from a typed anchor in the bytes.

Next question: `0x26f96aa` doubles two `impl_ntl.rs:664` totals when the byte at `+0x110c` of `rbx` is not 0. What is that
flag?
