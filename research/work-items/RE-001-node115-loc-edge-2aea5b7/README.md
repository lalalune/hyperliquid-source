# RE-001: map node #115 node/hl_node.rs:355 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2aea5b7` (file offset `0x2ae95b7`), `4c8d05ead89503` decodes as `lea r8, [rip + 0x395d8ea]`. Adding the signed displacement `60152042` to the next instruction VA `0x2aea5be` yields `0x6447ea8`. The decode from the start of FDE range `[0x2ae7fd0, 0x2aeaef0)` reaches that instruction boundary. The FDE itself is at `0x117c544`.

At `0x6447ea8` (file offset `0x6445ea8`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `13000000000000006301000055000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 355 and 85. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2aea162` is `0x2aea5a4` and the fallthrough is `0x2aea168`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, rax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2aea15f` | `4939c6` | `cmp r14, rax` |
| `0x2aea162` | `0f843c040000` | `je 0x2aea5a4` |
| `0x2aea5a4` | `4c896c2470` | `mov qword ptr [rsp + 0x70], r13` |
| `0x2aea5a9` | `488d3d92afb1fd` | `lea rdi, [rip - 0x24e506e]` |
| `0x2aea5b0` | `488d0db1cd9503` | `lea rcx, [rip + 0x395cdb1]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 60772562 added to `0x2aea5ce` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2aea5be` | `488d542470` | `lea rdx, [rsp + 0x70]` |
| `0x2aea5c3` | `be2b000000` | `mov esi, 0x2b` |
| `0x2aea5c8` | `ff15d2509f03` | `call qword ptr [rip + 0x39f50d2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6447ea8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2ae7fd0 --stop-address=0x2aea5ce "$target"
od -An -tx1 -j 105143984 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05ebd89503`), re-decoding lands at `0x6447ea9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 355, column 85. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
