# RE-001: map node #115 l1/evm/hyper_evm.rs:120 conditional call edge

- Component allocation: `evm`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/evm/hyper_evm.rs` as an embedded path. At ELF VA `0x548c307` (file offset `0x548b307`), `488d15e2de0101` decodes as `lea rdx, [rip + 0x101dee2]`. Adding the signed displacement `16899810` to the next instruction VA `0x548c30e` yields `0x64aa1f0`. The decode from the start of FDE range `[0x54897e0, 0x548c8e0)` reaches that instruction boundary. The FDE itself is at `0x1353090`.

At `0x64aa1f0` (file offset `0x64a81f0`), an `R_X86_64_RELATIVE` relocation points to `0x43ad8a` in `.rodata`. The next 16 bytes, `17000000000000007800000011000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 120 and 17. The string's normalized suffix matches `l1/evm/hyper_evm.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5489d3b` is `0x548c300` and the fallthrough is `0x5489d41`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [r12 + 0x37d8], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5489d32` | `4180bc24d837000000` | `cmp byte ptr [r12 + 0x37d8], 0` |
| `0x5489d3b` | `0f84bf250000` | `je 0x548c300` |
| `0x548c300` | `488d3dc1d749fb` | `lea rdi, [rip - 0x4b6283f]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 17118111 added to `0x548c319` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x548c30e` | `be31000000` | `mov esi, 0x31` |
| `0x548c313` | `ff159f330501` | `call qword ptr [rip + 0x105339f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa1f0 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x54897e0 --stop-address=0x548c319 "$target"
od -An -tx1 -j 105546232 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43ad8a --stop-address=0x43ada1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15e3de0101`), re-decoding lands at `0x64aa1f1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 120, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
