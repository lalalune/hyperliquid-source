# RE-001: map node #115 l1/qtys/mod.rs:848 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x448827d` (file offset `0x448727d`), `4c8d056c370002` decodes as `lea r8, [rip + 0x200376c]`. Adding the signed displacement `33568620` to the next instruction VA `0x4488284` yields `0x648b9f0`. The decode from the start of FDE range `[0x44881b0, 0x44882ff)` reaches that instruction boundary. The FDE itself is at `0xebce34`.

At `0x648b9f0` (file offset `0x64899f0`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000005003000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 848 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x448826d` is `0x448829b` and the fallthrough is `0x448826f`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test rbx, rbx`. The recorded edge is selected when the `jns` predicate (`SF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x448826a` | `4885db` | `test rbx, rbx` |
| `0x448826d` | `792c` | `jns 0x448829b` |
| `0x448826f` | `488d3d9caf34fc` | `lea rdi, [rip - 0x3cb5064]` |
| `0x4488276` | `488d0d1b430002` | `lea rcx, [rip + 0x200431b]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33911820 added to `0x4488294` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4488284` | `488d54240f` | `lea rdx, [rsp + 0xf]` |
| `0x4488289` | `be2b000000` | `mov esi, 0x2b` |
| `0x448828e` | `ff150c740502` | `call qword ptr [rip + 0x205740c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b9f0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44881b0 --stop-address=0x4488294 "$target"
od -An -tx1 -j 105421304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d056d370002`), re-decoding lands at `0x648b9f1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 848, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
