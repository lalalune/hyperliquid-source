# RE-001: map node #115 l1/qtys/impl_sz.rs:9 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/impl_sz.rs` as an embedded path. At ELF VA `0x4483449` (file offset `0x4482449`), `488d3520870002` decodes as `lea rsi, [rip + 0x2008720]`. Adding the signed displacement `33589024` to the next instruction VA `0x4483450` yields `0x648bb70`. The decode from the start of FDE range `[0x44831a0, 0x44834f3)` reaches that instruction boundary. The FDE itself is at `0xebc8ac`.

At `0x648bb70` (file offset `0x6489b70`), an `R_X86_64_RELATIVE` relocation points to `0x446e52` in `.rodata`. The next 16 bytes, `16000000000000000900000001000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 9 and 1. The string's normalized suffix matches `l1/qtys/impl_sz.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4483319` is `0x4483449` and the fallthrough is `0x448331f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r13, r13`. The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4483316` | `4d85ed` | `test r13, r13` |
| `0x4483319` | `0f882a010000` | `js 0x4483449` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 33954365 added to `0x448346b` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4483450` | `48897c2410` | `mov qword ptr [rsp + 0x10], rdi` |
| `0x4483455` | `31ff` | `xor edi, edi` |
| `0x4483457` | `4c890424` | `mov qword ptr [rsp], r8` |
| `0x448345b` | `4c89542408` | `mov qword ptr [rsp + 8], r10` |
| `0x4483460` | `4c895c2418` | `mov qword ptr [rsp + 0x18], r11` |
| `0x4483465` | `ff153d1a0602` | `call qword ptr [rip + 0x2061a3d]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648bb70 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44831a0 --stop-address=0x448346b "$target"
od -An -tx1 -j 105421688 -N 16 "$target"
objdump -s -j .rodata --start-address=0x446e52 --stop-address=0x446e68 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3521870002`), re-decoding lands at `0x648bb71`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 9, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
