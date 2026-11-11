# RE-001: map node #115 base/wallet.rs:31 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/wallet.rs` as an embedded path. At ELF VA `0x1588912` (file offset `0x1587912`), `4c8d05ef67e704` decodes as `lea r8, [rip + 0x4e767ef]`. Adding the signed displacement `82274287` to the next instruction VA `0x1588919` yields `0x63ff108`. The decode from the start of FDE range `[0x1588750, 0x1588946)` reaches that instruction boundary. The FDE itself is at `0x1053304`.

At `0x63ff108` (file offset `0x63fd108`), an `R_X86_64_RELATIVE` relocation points to `0x4388f2` in `.rodata`. The next 16 bytes, `12000000000000001f00000042000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 31 and 66. The string's normalized suffix matches `base/wallet.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x15887b9` is `0x15888f5` and the fallthrough is `0x15887bf`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp al, 2`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15887b7` | `3c02` | `cmp al, 2` |
| `0x15887b9` | `0f8436010000` | `je 0x15888f5` |
| `0x15888f5` | `c644241803` | `mov byte ptr [rsp + 0x18], 3` |
| `0x15888fa` | `4c897c2420` | `mov qword ptr [rsp + 0x20], r15` |
| `0x15888ff` | `48894c2428` | `mov qword ptr [rsp + 0x28], rcx` |
| `0x1588904` | `488d3d5bfbedfe` | `lea rdi, [rip - 0x11204a5]` |
| `0x158890b` | `488d0d4668e704` | `lea rcx, [rip + 0x4e76846]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 83193207 added to `0x1588929` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1588919` | `488d542418` | `lea rdx, [rsp + 0x18]` |
| `0x158891e` | `be2b000000` | `mov esi, 0x2b` |
| `0x1588923` | `ff15776df504` | `call qword ptr [rip + 0x4f56d77]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63ff108 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1588750 --stop-address=0x1588929 "$target"
od -An -tx1 -j 104845584 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4388f2 --stop-address=0x438904 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05f067e704`), re-decoding lands at `0x63ff109`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 31, column 66. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
