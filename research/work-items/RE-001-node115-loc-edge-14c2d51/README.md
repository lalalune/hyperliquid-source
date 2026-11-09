# RE-001: map node #115 base/bucket_guard.rs:66 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/bucket_guard.rs` as an embedded path. At ELF VA `0x14c2d51` (file offset `0x14c1d51`), `4c8d057060f304` decodes as `lea r8, [rip + 0x4f36070]`. Adding the signed displacement `83058800` to the next instruction VA `0x14c2d58` yields `0x63f8dc8`. The decode from the start of FDE range `[0x14c2c50, 0x14c2d82)` reaches that instruction boundary. The FDE itself is at `0x1046d1c`.

At `0x63f8dc8` (file offset `0x63f6dc8`), an `R_X86_64_RELATIVE` relocation points to `0x43b88a` in `.rodata`. The next 16 bytes, `18000000000000004200000054000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 66 and 84. The string's normalized suffix matches `base/bucket_guard.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x14c2d38` is `0x14c2d00` and the fallthrough is `0x14c2d3a`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp dword ptr [rsp + 8], 1`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x14c2d33` | `837c240801` | `cmp dword ptr [rsp + 8], 1` |
| `0x14c2d38` | `75c6` | `jne 0x14c2d00` |
| `0x14c2d3a` | `488b442410` | `mov rax, qword ptr [rsp + 0x10]` |
| `0x14c2d3f` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x14c2d43` | `488d3d801cfafe` | `lea rdi, [rip - 0x105e380]` |
| `0x14c2d4a` | `488d0d2f61f304` | `lea rcx, [rip + 0x4f3612f]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 84003130 added to `0x14c2d66` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x14c2d58` | `4889e2` | `mov rdx, rsp` |
| `0x14c2d5b` | `be2b000000` | `mov esi, 0x2b` |
| `0x14c2d60` | `ff153ac90105` | `call qword ptr [rip + 0x501c93a]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63f8dc8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x14c2c50 --stop-address=0x14c2d66 "$target"
od -An -tx1 -j 104820176 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43b88a --stop-address=0x43b8a2 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d057160f304`), re-decoding lands at `0x63f8dc9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 66, column 84. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
