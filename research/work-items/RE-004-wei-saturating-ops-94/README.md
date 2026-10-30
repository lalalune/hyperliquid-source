# RE-004: what does node #94 do when a Wei add or subtract overflows?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the site list, operation kinds, recorder calls and saturated values on the tested
  vectors; inference that the operands are Wei and that the map is unused state; unresolved for what the operands mean.
- Scope included and excluded: included are 107 of the 117 references to one Rust Location, in 71 functions. Excluded are
  the 10 references in functions that other work items name, the origin of each operand, Wei arithmetic that does not
  pass this Location, and node #115.

## Reproduce

Run from the repository root. Linux x86-64, Python standard library, GNU objdump (2.42). The tool reads the
binary and never runs it. No network and no side effects outside `--out`.

```
python3 tools/artifacts.py verify
python3 tools/wei_saturating_ops.py --out research/work-items/RE-004-wei-saturating-ops-94
python3 -m unittest discover -s tests -p 'test_wei_saturating_ops.py'
(cd research/work-items/RE-004-wei-saturating-ops-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x28d5491 --stop-address=0x28d54b1 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x372d891 --stop-address=0x372d8ad artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x358dcd0 --stop-address=0x358dd55 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF VAs. Function extents come from FDEs reached through `.eh_frame_hdr`, 121299 entries.

**Anchor.** The record at 0x56dfd90 is a Rust Location, `l1/src/qtys/impl_wei.rs:6:1`. Its path pointer is a RELATIVE
relocation. A byte scan finds 117 `lea r64,[rip+disp32]` references in `.text`, in 81 functions, and no relocation
points at the record. Each analysed site passes it in rsi with dil = 0 to the recorder 0x358dcd0, through GOT slot
0x5773190. Two sites load the slot into rbx earlier and use `call rbx`.

**Left out.** 10 of the 81 functions are named by another work item, and each holds one site. `evidence.json` lists them:
5 in RE-004-wei-buffered-cap-94 (the saturating +1e6 tail), 3 in RE-004-ntl-ten-thousand-add-94 (a separate packet, not in
main at the source commit) and 2 in RE-010-exchange-handlers. This packet makes no claim about those 10 sites.

**Kinds.** `wei-sites.tsv` has one row for each conditional edge into a site, 118 rows over 107 sites. The kind comes
from the instruction that sets the carry flag and the sense of the branch:

| Kind | Guard form | Guards | Goes on with |
|---|---|---|---|
| add | `add x,y` with carry | 48 | u64::MAX |
| add | `cmp sum,y` with borrow, where the site recomputes `sum` from y | 2 | u64::MAX |
| sub | `sub x,y` with borrow | 40 | 0 |
| sub | `cmp x,y` with borrow | 28 | 0 |

That gives 42 add sites and 65 sub sites. No site has guards of both kinds, and both kinds share the one Location.

The two usual shapes, from 0x28d5491 and 0x372d891:

```
xor edi,edi; lea rsi,[Location]; call recorder       sub rbx,[rsp+0x70]; jae ok
add r14,r12; mov rax,-1; cmovb r14,rax               lea rsi,[Location]; xor ebx,ebx; xor edi,edi; call recorder
```

**No panic at these sites.** The recorder returns, and each site then goes on. In every vector run the overflow path
reached an address that the matching non-overflow path also reaches, with one more recorder call and no other
difference in behaviour that the checks can see.

**Result at the common address.** For each overflowing pair (a, b), a second run uses a pair that does not overflow and
gives the saturated result: a + b = u64::MAX, or a = b. A third run uses another result.

- Value, 107 guards: a location agrees between the first two runs, differs in the third, and holds the exact result.
- Floor by 100, 7 guards: the location agrees and differs in the same way, but holds floor(result / 100). All 7 load
  +0x48 and +0x50, and 3 of them go on to `cvtsi2sd xmm2,rdx`, so the location there is a double. The non-overflow path
  divides with `shr rax,2; mul 0x28f5c28f5c28f5c3; shr rdx,2`. 25 * m - 2^66 = 11, and 2^62 * 11 < 2^66, so that is
  floor(x / 100) for every u64. On overflow these guards go on with 0, which is what floor(0 / 100) gives.
- Derived, 1 guard: 0x3745ce9, where a second subtract follows at once, so the location holds a later value.
- Branch, 3 guards: at 0x275282f, 0x3757402 and 0x3c017cd no location holds the result at the common address. The
  result only decides a branch: another result leaves the path, the callee-saved registers do not differ, and the
  overflow run compares nothing the other run does not.

**Recorder.** The recorder and map code below were read by hand. The tool pins the facts marked with a star.

- 0x358dcd0 takes a lock word at 0x5786278, copies the Location to the stack, and passes `dil` as a byte key (*) to
  0x3396b10 (*), then releases the lock and returns.
- 0x3396b10 has the shape of a B-tree insert with a byte key: key bytes from node +0x114, a u16 count at +0x112, 24-byte
  values and node capacity 11 (*). An equal key overwrites the old value and nothing is counted.
- Its own non-returning exits are an allocation failure and the `idx < CAPACITY` assertion. Its node-split path through
  0x2f61f70 was not read.
- 0x358db60 moves the map out, drops it through 0x33f64b0 and leaves it empty. It is reached through GOT slot 0x5773e18,
  with 3 references (*) at 0x2359937, 0x4cae247 and 0x4cb6bd7.
- A byte scan finds rip-relative operands in 0x5786278..0x57862a0 only in 0x358db60 and 0x358dcd0 (*), and no relocation
  into that range (*).

**Reference comparison.** `l1/qtys/impl_wei.rs` lines 631-652 implement `Add` and `Sub` for `Wei` with `expect` on
`checked_add` and `checked_sub`, so the reference panics on overflow. Node #94 does not panic at these 107 sites, and
neither reference message occurs in the binary. Its comment at lines 17-19, that availability paths saturate the free
bucket to zero after logging, fits the sub sites, but applies at every sub site here rather than at several. No literal
`/ 100` appears under `l1/qtys` or `l1/spot_clearinghouse`, though the reference could reach one through its power table.

## Implementation and comparison

Rust implementation: not yet implemented. Nothing was compiled, so there is no build, Cargo.lock or byte comparison.

The comparison here is real instructions against saturating add and subtract. A Python evaluator interprets objdump text.
All registers and memory start as random marks. A run starts at the top of the straight code before the flag setter.
At the flag setter, every location holding an operand's mark is rewritten with the vector value, so copies stay
consistent. There are 6 overflowing pairs for each kind and 2 seeds. Unmodelled instructions leave a fresh mark and
clear the flags, so a result depending on one cannot match. A branch on unknown flags, an unknown call or `ud2` ends
the run.

Results: 118 of 118 guards over 107 of 107 analysed sites pass, in 9956 evaluator runs.

`mutation-controls.tsv` damages each site in the listing and repeats the check:

- Dropping the recorder call fails at 107 of 107 sites.
- Changing the saturated value to 5 fails at 106 of 106 sites that have such an instruction. The walk follows one `jmp`,
  because some sites jump to a shared `xor eax,eax` just before the common address.
- 0x3c017cd has no such instruction. Its cold path jumps past a compare of the result, so nothing there holds a value.

Early versions of the check passed mutations. The compare log and the callee-saved test exist because of those survivors.

## Results and limitations

Metrics are in `evidence.json`. Denominators: 107 of 117 Location references analysed, 10 left out by name, 118 of 118
guards passing, 213 of 213 available mutation controls caught. No progress gate is requested.

- These are boundary vectors, not a proof over all u64. The guards read the carry flag directly, and the paired runs test
  the edge itself (a + b = u64::MAX, a = b), but the tool does not prove the cold path for all operands.
- Runs start mid-function. Relations between registers and memory from before the window are unknown. A reload across
  the window can differ from a register copy in its marks, so the compare log accepts a pair that matches on the side
  holding the result. That is a relaxed rule.
- 7 guards show the result only after a divide, 1 only after a later subtract and 3 only through a branch. For those
  the exact result is not read back.
- Only sites passing this Location are covered. Wei arithmetic that uses `checked_*`, wraps, or passes another Location
  is outside the packet, so this does not show that no Wei operation can panic.
- That the operands are Wei rests on the Location's file name. Operand meaning is unresolved. 25 guards read the fields
  +0x48 and +0x50, which look like a pair of balances, but nothing here proves that.
- The recorder's contended lock paths were not followed. The rip scan does not see an address built from a lower base.
- Node #115 is not covered.

Next question: what are the two fields at +0x48 and +0x50 read by those 25 guards, and does floor(difference / 100) at 7
of them convert a Wei amount to another unit?
