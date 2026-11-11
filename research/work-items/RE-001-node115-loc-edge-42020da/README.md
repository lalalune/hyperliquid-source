# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:358 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x42020da` (file offset `0x42010da`), `488d152f1e2802` decodes as `lea rdx, [rip + 0x2281e2f]`. Adding the signed displacement `36183599` to the next instruction VA `0x42020e1` yields `0x6483f10`. The decode from the start of FDE range `[0x4201dd0, 0x42020ec)` reaches that instruction boundary. The FDE itself is at `0xe88e24`.

At `0x6483f10` (file offset `0x6481f10`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `25000000000000006601000033000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 358 and 51. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4201f5c` is `0x42020d3` and the fallthrough is `0x4201f62`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rax], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4201f59` | `803800` | `cmp byte ptr [rax], 0` |
| `0x4201f5c` | `0f8471010000` | `je 0x42020d3` |
| `0x42020d3` | `488d3d1b695cfc` | `lea rdi, [rip - 0x3a396e5]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 36558404 added to `0x42020ec` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x42020e1` | `be28000000` | `mov esi, 0x28` |
| `0x42020e6` | `ff1544d62d02` | `call qword ptr [rip + 0x22dd644]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483f10 '
readelf -rW "$target" | grep -i '0*64df730 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4201dd0 --stop-address=0x42020ec "$target"
od -An -tx1 -j 105389848 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15301e2802`), re-decoding lands at `0x6483f11`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 358, column 51. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
