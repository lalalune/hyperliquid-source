# RE-001: map node #115 base/lazy_mutex.rs:46 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `base/lazy_mutex.rs` as an embedded path. At ELF VA `0x150b62e` (file offset `0x150a62e`), `488d0d7bd7ee04` decodes as `lea rcx, [rip + 0x4eed77b]`. Adding the signed displacement `82761595` to the next instruction VA `0x150b635` yields `0x63f8db0`. The decode from the start of FDE range `[0x150b310, 0x150baaf)` reaches that instruction boundary. The FDE itself is at `0x104b978`.

At `0x63f8db0` (file offset `0x63f6db0`), an `R_X86_64_RELATIVE` relocation points to `0x438756` in `.rodata`. The next 16 bytes, `16000000000000002e00000011000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 46 and 17. The string's normalized suffix matches `base/lazy_mutex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x150b4e2` establish a local edge into the argument setup. The taken target is `0x150b607` and the fallthrough is `0x150b4e8`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x150b4db` | `803d9e49fe0401` | `cmp byte ptr [rip + 0x4fe499e], 1` |
| `0x150b4e2` | `0f851f010000` | `jne 0x150b607` |
| `0x150b607` | `488d442410` | `lea rax, [rsp + 0x10]` |
| `0x150b60c` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x150b611` | `488d442478` | `lea rax, [rsp + 0x78]` |
| `0x150b616` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x150b61b` | `488d052648fe04` | `lea rax, [rip + 0x4fe4826]` |
| `0x150b622` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x150b627` | `488d3d3248fe04` | `lea rdi, [rip + 0x4fe4832]` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 264828 added to `0x150b644` gives `0x154c0c0`. The target's FDE at `0x10501a0` describes `[0x154c0c0, 0x154c2b5)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x150b635` | `488d742430` | `lea rsi, [rsp + 0x30]` |
| `0x150b63a` | `ba01000000` | `mov edx, 1` |
| `0x150b63f` | `e87c0a0400` | `call 0x154c0c0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63f8db0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x150b310 --stop-address=0x150b644 "$target"
od -An -tx1 -j 104820152 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438756 --stop-address=0x43876c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d7cd7ee04`), re-decoding lands at `0x63f8db1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 46, column 17. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
