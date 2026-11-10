# RE-001: map node #115 base/lock_id.rs:98 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lock_id.rs` as an embedded path. At ELF VA `0x2a251d7` (file offset `0x2a241d7`), `488d3d0aeca103` decodes as `lea rdi, [rip + 0x3a1ec0a]`. Adding the signed displacement `60943370` to the next instruction VA `0x2a251de` yields `0x6443de8`. The decode from the start of FDE range `[0x2a24be0, 0x2a254f7)` reaches that instruction boundary. The FDE itself is at `0x116ba54`.

At `0x6443de8` (file offset `0x6441de8`), an `R_X86_64_RELATIVE` relocation points to `0x444a53` in `.rodata`. The next 16 bytes, `1300000000000000620000001b000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 98 and 27. The string's normalized suffix matches `base/lock_id.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2a24f38` is `0x2a251d7` and the fallthrough is `0x2a24f3e`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr fs:[r12], 0`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a24f32` | `6449833c2400` | `cmp qword ptr fs:[r12], 0` |
| `0x2a24f38` | `0f8599020000` | `jne 0x2a251d7` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 61587708 added to `0x2a251e4` gives the relocation slot `0x64e12e0`. Its symbol-zero RELATIVE addend is `0x1680b70`. The target's FDE at `0xcc2fb4` describes `[0x1680b70, 0x1680b9f)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a251de` | `ff15fcc0ab03` | `call qword ptr [rip + 0x3abc0fc]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6443de8 '
readelf -rW "$target" | grep -i '0*64e12e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a24be0 --stop-address=0x2a251e4 "$target"
od -An -tx1 -j 105127408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444a53 --stop-address=0x444a66 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d0beca103`), re-decoding lands at `0x6443de9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 98, column 27. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
