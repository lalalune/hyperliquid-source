# RE-001: map node #115 l1/exchange/impl_vault.rs:314 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_vault.rs` as an embedded path. At ELF VA `0x2c41477` (file offset `0x2c40477`), `488d3d12c28003` decodes as `lea rdi, [rip + 0x380c212]`. Adding the signed displacement `58769938` to the next instruction VA `0x2c4147e` yields `0x644d690`. The decode from the start of FDE range `[0x2c3f5e0, 0x2c41707)` reaches that instruction boundary. The FDE itself is at `0x118c018`.

At `0x644d690` (file offset `0x644b690`), an `R_X86_64_RELATIVE` relocation points to `0x43f171` in `.rodata`. The next 16 bytes, `1d000000000000003a01000043000000`, decode as a little-endian 64-bit length of 29 and two 32-bit values, 314 and 67. The string's normalized suffix matches `l1/exchange/impl_vault.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c41087` is `0x2c41477` and the fallthrough is `0x2c4108d`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c41084` | `4885c0` | `test rax, rax` |
| `0x2c41087` | `0f84ea030000` | `je 0x2c41477` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 59368364 added to `0x2c41484` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c4147e` | `ff15ace38903` | `call qword ptr [rip + 0x389e3ac]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d690 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c3f5e0 --stop-address=0x2c41484 "$target"
od -An -tx1 -j 105166488 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43f171 --stop-address=0x43f18e "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d13c28003`), re-decoding lands at `0x644d691`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 314, column 67. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
