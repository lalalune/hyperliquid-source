# RE-001: map node #115 net_utils/rw_lock.rs:125 conditional call edge

- Component allocation: `transport`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `net_utils/rw_lock.rs` as an embedded path. At ELF VA `0x4e450e4` (file offset `0x4e440e4`), `4c8d054d9d6501` decodes as `lea r8, [rip + 0x1659d4d]`. Adding the signed displacement `23436621` to the next instruction VA `0x4e450eb` yields `0x649ee38`. The decode from the start of FDE range `[0x4e44fd0, 0x4e452bc)` reaches that instruction boundary. The FDE itself is at `0x130383c`.

At `0x649ee38` (file offset `0x649ce38`), an `R_X86_64_RELATIVE` relocation points to `0x432e59` in `.rodata`. The next 16 bytes, `18000000000000007d00000025000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 125 and 37. The string's normalized suffix matches `net_utils/rw_lock.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x4e45022` establish a local edge into the argument setup. The taken target is `0x4e450b7` and the fallthrough is `0x4e45028`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e4501d` | `807c240a00` | `cmp byte ptr [rsp + 0xa], 0` |
| `0x4e45022` | `0f848f000000` | `je 0x4e450b7` |
| `0x4e450b7` | `0f104500` | `movups xmm0, xmmword ptr [rbp]` |
| `0x4e450bb` | `0f11442438` | `movups xmmword ptr [rsp + 0x38], xmm0` |
| `0x4e450c0` | `48c744243000000000` | `mov qword ptr [rsp + 0x30], 0` |
| `0x4e450c9` | `4c897c2410` | `mov qword ptr [rsp + 0x10], r15` |
| `0x4e450ce` | `4981c730010000` | `add r15, 0x130` |
| `0x4e450d5` | `4c896c2418` | `mov qword ptr [rsp + 0x18], r13` |
| `0x4e450da` | `488d442430` | `lea rax, [rsp + 0x30]` |
| `0x4e450df` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 915843 added to `0x4e450fd` gives `0x4f24a80`. The target's FDE at `0x130b6dc` describes `[0x4f24a80, 0x4f253e2)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e450eb` | `488d542410` | `lea rdx, [rsp + 0x10]` |
| `0x4e450f0` | `4889df` | `mov rdi, rbx` |
| `0x4e450f3` | `4c89fe` | `mov rsi, r15` |
| `0x4e450f6` | `31c9` | `xor ecx, ecx` |
| `0x4e450f8` | `e883f90d00` | `call 0x4f24a80` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649ee38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4e44fd0 --stop-address=0x4e450fd "$target"
od -An -tx1 -j 105500224 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432e59 --stop-address=0x432e71 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d054e9d6501`), re-decoding lands at `0x649ee39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 125, column 37. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
