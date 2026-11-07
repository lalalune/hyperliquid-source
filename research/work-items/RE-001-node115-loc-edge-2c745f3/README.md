# RE-001: map node #115 l1/evm/hyper_evm.rs:120 conditional call edge

- Component allocation: `evm`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/evm/hyper_evm.rs` as an embedded path. At ELF VA `0x2c745f3` (file offset `0x2c735f3`), `488d15c6f67c03` decodes as `lea rdx, [rip + 0x37cf6c6]`. Adding the signed displacement `58521286` to the next instruction VA `0x2c745fa` yields `0x6443cc0`. The decode from the start of FDE range `[0x2c71eb0, 0x2c74a69)` reaches that instruction boundary. The FDE itself is at `0x118dfe0`.

At `0x6443cc0` (file offset `0x6441cc0`), an `R_X86_64_RELATIVE` relocation points to `0x43ad8a` in `.rodata`. The next 16 bytes, `17000000000000007800000011000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 120 and 17. The string's normalized suffix matches `l1/evm/hyper_evm.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c71ee1` is `0x2c745ec` and the fallthrough is `0x2c71ee7`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rsi + 0x37d8], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c71eda` | `80bed837000000` | `cmp byte ptr [rsi + 0x37d8], 0` |
| `0x2c71ee1` | `0f8405270000` | `je 0x2c745ec` |
| `0x2c745ec` | `488d3dddd998fd` | `lea rdi, [rip - 0x2672623]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 59158707 added to `0x2c74605` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c745fa` | `be31000000` | `mov esi, 0x31` |
| `0x2c745ff` | `ff15b3b08603` | `call qword ptr [rip + 0x386b0b3]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6443cc0 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c71eb0 --stop-address=0x2c74605 "$target"
od -An -tx1 -j 105127112 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43ad8a --stop-address=0x43ada1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15c7f67c03`), re-decoding lands at `0x6443cc1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 120, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
