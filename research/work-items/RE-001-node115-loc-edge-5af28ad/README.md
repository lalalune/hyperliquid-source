# RE-001: map node #115 l1/exchange/impl_outcome.rs:355 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_outcome.rs` as an embedded path. At ELF VA `0x5af28ad` (file offset `0x5af18ad`), `488d35347c9b00` decodes as `lea rsi, [rip + 0x9b7c34]`. Adding the signed displacement `10189876` to the next instruction VA `0x5af28b4` yields `0x64aa4e8`. The decode from the start of FDE range `[0x5af2180, 0x5af3981)` reaches that instruction boundary. The FDE itself is at `0x13b26dc`.

At `0x64aa4e8` (file offset `0x64a84e8`), an `R_X86_64_RELATIVE` relocation points to `0x445ed1` in `.rodata`. The next 16 bytes, `1f000000000000006301000032000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 355 and 50. The string's normalized suffix matches `l1/exchange/impl_outcome.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5af28a0` is `0x5af292d` and the fallthrough is `0x5af28a6`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 0x1a3`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5af289b` | `3da3010000` | `cmp eax, 0x1a3` |
| `0x5af28a0` | `0f8587000000` | `jne 0x5af292d` |
| `0x5af28a6` | `c685a802000001` | `mov byte ptr [rbp + 0x2a8], 1` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 10429929 added to `0x5af28bf` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5af28b4` | `bf04000000` | `mov edi, 4` |
| `0x5af28b9` | `ff15e9259f00` | `call qword ptr [rip + 0x9f25e9]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa4e8 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5af2180 --stop-address=0x5af28bf "$target"
od -An -tx1 -j 105546992 -N 16 "$target"
objdump -s -j .rodata --start-address=0x445ed1 --stop-address=0x445ef0 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35357c9b00`), re-decoding lands at `0x64aa4e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 355, column 50. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
