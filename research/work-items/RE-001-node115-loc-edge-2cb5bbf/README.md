# RE-001: map node #115 node/hl_node.rs:355 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2cb5bbf` (file offset `0x2cb4bbf`), `4c8d0582867903` decodes as `lea r8, [rip + 0x3798682]`. Adding the signed displacement `58295938` to the next instruction VA `0x2cb5bc6` yields `0x644e248`. The decode from the start of FDE range `[0x2cb37d0, 0x2cb64f1)` reaches that instruction boundary. The FDE itself is at `0x1196888`.

At `0x644e248` (file offset `0x644c248`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `13000000000000006301000055000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 355 and 85. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2cb5809` is `0x2cb5bac` and the fallthrough is `0x2cb580f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, rax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cb5806` | `4939c6` | `cmp r14, rax` |
| `0x2cb5809` | `0f849d030000` | `je 0x2cb5bac` |
| `0x2cb5bac` | `48896c2470` | `mov qword ptr [rsp + 0x70], rbp` |
| `0x2cb5bb1` | `488d3d429095fd` | `lea rdi, [rip - 0x26a6fbe]` |
| `0x2cb5bb8` | `488d0d19817903` | `lea rcx, [rip + 0x3798119]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 58890954 added to `0x2cb5bd6` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cb5bc6` | `488d542470` | `lea rdx, [rsp + 0x70]` |
| `0x2cb5bcb` | `be2b000000` | `mov esi, 0x2b` |
| `0x2cb5bd0` | `ff15ca9a8203` | `call qword ptr [rip + 0x3829aca]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644e248 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2cb37d0 --stop-address=0x2cb5bd6 "$target"
od -An -tx1 -j 105169488 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0583867903`), re-decoding lands at `0x644e249`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 355, column 85. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
