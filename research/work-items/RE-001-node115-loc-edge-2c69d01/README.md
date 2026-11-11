# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:17 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x2c69d01` (file offset `0x2c68d01`), `4c8d05a01c8203` decodes as `lea r8, [rip + 0x3821ca0]`. Adding the signed displacement `58858656` to the next instruction VA `0x2c69d08` yields `0x648b9a8`. The decode from the start of FDE range `[0x2c69b70, 0x2c69d35)` reaches that instruction boundary. The FDE itself is at `0x118dac8`.

At `0x648b9a8` (file offset `0x64899a8`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000001100000021000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 17 and 33. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c69b8e` is `0x2c69cec` and the fallthrough is `0x2c69b94`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rsi + 0x7d0], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c69b86` | `4883bed007000000` | `cmp qword ptr [rsi + 0x7d0], 0` |
| `0x2c69b8e` | `0f8458010000` | `je 0x2c69cec` |
| `0x2c69cec` | `66c74424305601` | `mov word ptr [rsp + 0x30], 0x156` |
| `0x2c69cf3` | `488d3d1895b6fd` | `lea rdi, [rip - 0x2496ae8]` |
| `0x2c69cfa` | `488d0df7288203` | `lea rcx, [rip + 0x38228f7]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 59201928 added to `0x2c69d18` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c69d08` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x2c69d0d` | `be2b000000` | `mov esi, 0x2b` |
| `0x2c69d12` | `ff1588598703` | `call qword ptr [rip + 0x3875988]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b9a8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c69b70 --stop-address=0x2c69d18 "$target"
od -An -tx1 -j 105421232 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05a11c8203`), re-decoding lands at `0x648b9a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 17, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
