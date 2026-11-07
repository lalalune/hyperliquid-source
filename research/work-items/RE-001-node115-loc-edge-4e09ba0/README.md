# RE-001: map node #115 node/stream_msg.rs:43 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/stream_msg.rs` as an embedded path. At ELF VA `0x4e09ba0` (file offset `0x4e08ba0`), `4c8d0539336901` decodes as `lea r8, [rip + 0x1693339]`. Adding the signed displacement `23671609` to the next instruction VA `0x4e09ba7` yields `0x649cee0`. The decode from the start of FDE range `[0x4e09ab0, 0x4e09bff)` reaches that instruction boundary. The FDE itself is at `0x1300924`.

At `0x649cee0` (file offset `0x649aee0`), an `R_X86_64_RELATIVE` relocation points to `0x445fdf` in `.rodata`. The next 16 bytes, `16000000000000002b00000030000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 43 and 48. The string's normalized suffix matches `node/stream_msg.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4e09b74` is `0x4e09b83` and the fallthrough is `0x4e09b76`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e09b71` | `4885f6` | `test rsi, rsi` |
| `0x4e09b74` | `740d` | `je 0x4e09b83` |
| `0x4e09b83` | `48895c2418` | `mov qword ptr [rsp + 0x18], rbx` |
| `0x4e09b88` | `4c89742420` | `mov qword ptr [rsp + 0x20], r14` |
| `0x4e09b8d` | `4c897c2428` | `mov qword ptr [rsp + 0x28], r15` |
| `0x4e09b92` | `488d3d59d6b0fb` | `lea rdi, [rip - 0x44f29a7]` |
| `0x4e09b99` | `488d0db8306901` | `lea rcx, [rip + 0x16930b8]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 23943913 added to `0x4e09bb7` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e09ba7` | `488d542418` | `lea rdx, [rsp + 0x18]` |
| `0x4e09bac` | `be2b000000` | `mov esi, 0x2b` |
| `0x4e09bb1` | `ff15e95a6d01` | `call qword ptr [rip + 0x16d5ae9]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649cee0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4e09ab0 --stop-address=0x4e09bb7 "$target"
od -An -tx1 -j 105492200 -N 16 "$target"
objdump -s -j .rodata --start-address=0x445fdf --stop-address=0x445ff5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d053a336901`), re-decoding lands at `0x649cee1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 43, column 48. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
