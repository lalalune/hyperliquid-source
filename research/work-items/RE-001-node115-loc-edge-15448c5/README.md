# RE-001: map node #115 base/crit_msg.rs:648 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/crit_msg.rs` as an embedded path. At ELF VA `0x15448c5` (file offset `0x15438c5`), `488d151c79eb04` decodes as `lea rdx, [rip + 0x4eb791c]`. Adding the signed displacement `82540828` to the next instruction VA `0x15448cc` yields `0x63fc1e8`. The decode from the start of FDE range `[0x15444d0, 0x154498b)` reaches that instruction boundary. The FDE itself is at `0x104facc`.

At `0x63fc1e8` (file offset `0x63fa1e8`), an `R_X86_64_RELATIVE` relocation points to `0x43fea4` in `.rodata`. The next 16 bytes, `1400000000000000880200000d000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 648 and 13. The string's normalized suffix matches `base/crit_msg.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1544646` is `0x15448be` and the fallthrough is `0x154464c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1544644` | `84c0` | `test al, al` |
| `0x1544646` | `0f8572020000` | `jne 0x15448be` |
| `0x15448be` | `488d3d7a12f2fe` | `lea rdi, [rip - 0x10ded86]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 83471961 added to `0x15448d7` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15448cc` | `be3d000000` | `mov esi, 0x3d` |
| `0x15448d1` | `ff1559aef904` | `call qword ptr [rip + 0x4f9ae59]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fc1e8 '
readelf -rW "$target" | grep -i '0*64df730 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x15444d0 --stop-address=0x15448d7 "$target"
od -An -tx1 -j 104833520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43fea4 --stop-address=0x43feb8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d151d79eb04`), re-decoding lands at `0x63fc1e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 648, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
