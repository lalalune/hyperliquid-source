# RE-001: map node #115 node/consensus/server.rs:221 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/consensus/server.rs` as an embedded path. At ELF VA `0x2a5029f` (file offset `0x2a4f29f`), `488d15623d9f03` decodes as `lea rdx, [rip + 0x39f3d62]`. Adding the signed displacement `60767586` to the next instruction VA `0x2a502a6` yields `0x6444008`. The decode from the start of FDE range `[0x2a4fc50, 0x2a5031f)` reaches that instruction boundary. The FDE itself is at `0x116d884`.

At `0x6444008` (file offset `0x6442008`), an `R_X86_64_RELATIVE` relocation points to `0x432bae` in `.rodata`. The next 16 bytes, `1c00000000000000dd0000001e000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 221 and 30. The string's normalized suffix matches `node/consensus/server.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2a4fd80` is `0x2a50298` and the fallthrough is `0x2a4fd86`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a4fd7d` | `4885f6` | `test rsi, rsi` |
| `0x2a4fd80` | `0f8412050000` | `je 0x2a50298` |
| `0x2a50298` | `488d3d671ebbfd` | `lea rdi, [rip - 0x244e199]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 61404351 added to `0x2a502b1` gives the relocation slot `0x64df770`. Its symbol-zero RELATIVE addend is `0x1680bd0`. The target's FDE at `0xcc2fec` describes `[0x1680bd0, 0x1680c04)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a502a6` | `be4a000000` | `mov esi, 0x4a` |
| `0x2a502ab` | `ff15bff4a803` | `call qword ptr [rip + 0x3a8f4bf]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6444008 '
readelf -rW "$target" | grep -i '0*64df770 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a4fc50 --stop-address=0x2a502b1 "$target"
od -An -tx1 -j 105127952 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432bae --stop-address=0x432bca "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15633d9f03`), re-decoding lands at `0x6444009`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 221, column 30. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
