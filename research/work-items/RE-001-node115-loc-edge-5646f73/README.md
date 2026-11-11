# RE-001: map node #115 node/gossip_config.rs:439 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/gossip_config.rs` as an embedded path. At ELF VA `0x5646f73` (file offset `0x5645f73`), `488d3dde3fe600` decodes as `lea rdi, [rip + 0xe63fde]`. Adding the signed displacement `15089630` to the next instruction VA `0x5646f7a` yields `0x64aaf58`. The decode from the start of FDE range `[0x56467d0, 0x56471a8)` reaches that instruction boundary. The FDE itself is at `0x13670a4`.

At `0x64aaf58` (file offset `0x64a8f58`), an `R_X86_64_RELATIVE` relocation points to `0x449029` in `.rodata`. The next 16 bytes, `1900000000000000b701000051000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 439 and 81. The string's normalized suffix matches `node/gossip_config.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5646a41` is `0x5646f73` and the fallthrough is `0x5646a47`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5646a3e` | `4839c8` | `cmp rax, rcx` |
| `0x5646a41` | `0f842c050000` | `je 0x5646f73` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 15304880 added to `0x5646f80` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5646f7a` | `ff15b088e900` | `call qword ptr [rip + 0xe988b0]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aaf58 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x56467d0 --stop-address=0x5646f80 "$target"
od -An -tx1 -j 105549664 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449029 --stop-address=0x449042 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3ddf3fe600`), re-decoding lands at `0x64aaf59`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 439, column 81. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
