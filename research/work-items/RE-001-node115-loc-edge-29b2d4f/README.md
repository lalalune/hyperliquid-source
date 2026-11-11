# RE-001: map node #115 base/lock_id.rs:98 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lock_id.rs` as an embedded path. At ELF VA `0x29b2d4f` (file offset `0x29b1d4f`), `488d3d9210a903` decodes as `lea rdi, [rip + 0x3a91092]`. Adding the signed displacement `61411474` to the next instruction VA `0x29b2d56` yields `0x6443de8`. The decode from the start of FDE range `[0x29b26f0, 0x29b30bd)` reaches that instruction boundary. The FDE itself is at `0x11613bc`.

At `0x6443de8` (file offset `0x6441de8`), an `R_X86_64_RELATIVE` relocation points to `0x444a53` in `.rodata`. The next 16 bytes, `1300000000000000620000001b000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 98 and 27. The string's normalized suffix matches `base/lock_id.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x29b2a74` is `0x29b2d4f` and the fallthrough is `0x29b2a7a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr fs:[r12], 0`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29b2a6e` | `6449833c2400` | `cmp qword ptr fs:[r12], 0` |
| `0x29b2a74` | `0f85d5020000` | `jne 0x29b2d4f` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 62055812 added to `0x29b2d5c` gives the relocation slot `0x64e12e0`. Its symbol-zero RELATIVE addend is `0x1680b70`. The target's FDE at `0xcc2fb4` describes `[0x1680b70, 0x1680b9f)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29b2d56` | `ff1584e5b203` | `call qword ptr [rip + 0x3b2e584]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6443de8 '
readelf -rW "$target" | grep -i '0*64e12e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x29b26f0 --stop-address=0x29b2d5c "$target"
od -An -tx1 -j 105127408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444a53 --stop-address=0x444a66 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d9310a903`), re-decoding lands at `0x6443de9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 98, column 27. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
