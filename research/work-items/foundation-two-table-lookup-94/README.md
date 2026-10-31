# foundation-two-table-lookup-94

## Question

Bind one small, previously unclaimed window in node #94 whose rule reads
directly from its own bytes: a two-table lookup that picks one of two
8-byte-entry tables by a small gate and computes the index from its
arguments. No family census, no shared-primitive decode, no component map
is claimed.

## Target

- Node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (`artifacts/node/94/hl-node`).
- Window: `[0x5560660, 0x55606a8)`, 72 bytes, `.eh_frame+0x2d0108`,
  CIE at section offset 0, zR pcrel sdata4
  (field VA + `0x045af038` = `0x5560660`, range `0x48`),
  confirmed with GNU `objdump --dwarf=frames`.
- Padding: 8 `int3` bytes to the 80-byte stride ending at `0x55606b0`.
  Stride is not the FDE extent; the checker locks body and padding
  separately. Next FDE starts exactly at `0x55606b0`
  (`[0x55606b0, 0x55606cb)`).

## Scope

Included: the window's bytes, its FDE record, the next FDE record, the
one retained direct caller and its FDE record, the full `.rela.*` scan,
and the gate/index rule below.

Excluded: table contents (unknown, not claimed), caller purpose beyond the
call itself, any stdlib type or source-level function, any provenance for
the window, and any other window in `0x5560xxx`.

## Reproduce

```sh
objdump -d --start-address=0x5560660 --stop-address=0x55606b0 \
  artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node | grep -A 4 '5560660'
python3 tools/foundation_two_table_lookup.py \
  --check research/work-items/foundation-two-table-lookup-94/evidence.json
python3 -m unittest tests.test_foundation_two_table_lookup -v
make verify test catalogue-check
```

## Observations

Decoded behavior, verified from bytes, zero calls, two forward branches:

```text
endbr64
lea    -0x3(%rdi),%eax        # gate = low32(edi) - 3
cmp    $0x2,%eax
ja     0x5560671              # gate > 2 (unsigned) -> table1 path
cmp    $0x1,%esi
je     0x5560690              # low32(esi) == 1 -> table2 path
# table1 path:
movslq %edx,%rdx
movslq %edi,%rdi
lea    (%rdx,%rdx,4),%rax     # 5*edx
lea    (%rdi,%rax,2),%rdx     # edi + 10*edx
lea    0x20d35a(%rip),%rax    # -> 0x576d9e0
mov    (%rax,%rdx,8),%rax
ret
nopl   0x0(%rax,%rax,1)       # 5 bytes, inside the FDE body
# table2 path:
movslq %edx,%rdx
cltq                          # sign-extend eax (gate)
lea    (%rdx,%rdx,2),%rdx     # 3*edx
add    %rdx,%rax              # gate + 3*edx
lea    0x20d47d(%rip),%rdx    # -> 0x576db20
mov    (%rdx,%rax,8),%rax
ret
```

Rule: gate = low32(edi) − 3, compared unsigned; if gate ≤ 2 and
low32(esi) == 1, return table2[sign32(gate) + 3·sign32(edx)]; otherwise
return table1[sign32(edi) + 10·sign32(edx)]. Both tables hold 8-byte
entries (scale 8); both indices are sign-extended 32-bit values
(`movslq`/`cltq`), so a negative low32 edi or edx lowers the index
rather than wrapping to a huge unsigned offset.

Both table bases live in `.data.rel.ro`. Table2 − table1 = `0x140`
(320 bytes = 40 entries), but the tables' contents and lengths are not
claimed, and no entry value is read into the rule.

Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
exactly one direct `e8` site — `0x55c8554` (bytes `e8 07 81 f9 ff`),
confirmed as an
instruction start by linear disassembly from its caller FDE start
(`0x55c84f0..0x55c8bc3`). This scan is explicitly not a complete xref
census. The caller sets up the call in its own frame; caller purpose
beyond that is not claimed.

Data edge: no relocation record of any type in any `.rela.*` section
names this window as addend (full-section scan of `.rela.dyn` and
`.rela.plt`).

## Scout correction

The round-9 scout note listed the table bases as `0x5763be0` /
`0x5763b20` "by scout arithmetic". Both are wrong. The retained bytes
say otherwise, and `objdump`'s own rip-relative target comments agree:
table1 lea at `0x556067f` (next instruction `0x5560686`) +
displacement `0x20d35a` = `0x576d9e0`; table2 lea at `0x556069c`
(next instruction `0x55606a3`) + displacement `0x20d47d` =
`0x576db20`. The checker locks the verified bases, not the scout
summary. Everything else in the scout note verified exactly (FDE range,
72-byte body, both paths, one caller, no naming relocation).

Scout precision note (not a behavior correction): the scout listed the
caller FDE end as `0x55c8bd0`; the exact end from `--dwarf=frames` is
`0x55c8bc3` (the scout end is the following FDE start, the same pattern
seen in packets #50/#51/#53). The checker locks the exact end.

## Inferences

The "two-table lookup" label is an inference from the two rip-relative
bases and the gate selecting between them. The gate shape (a small
unsigned range plus a second-argument tag) suggests a dispatch on a
small enum-like first argument, but no enum, type, or meaning is
claimed.

## Unknowns

- What either table holds, and how many entries each has.
- What the gate values 3..5 (table2 rows) or any table1 row means.
- The caller's purpose and the meaning of its arguments.
- Whether any indirect or PLT path reaches this window (the scan covers
  direct `e8` sites only).

## Limits

- The byte-pattern scan is not a complete xref census, and the absence
  of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94.
- Static analysis only. The captured binary was never executed; no
  network, chain action, or signing was involved.
