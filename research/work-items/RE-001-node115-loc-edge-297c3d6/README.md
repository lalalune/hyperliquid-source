# RE-001: map node #115 l1/dex_registry/perp_dex.rs:29 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/perp_dex.rs` as an embedded path. At ELF VA `0x297c3d6` (file offset `0x297b3d6`), `4c8d052b7ab003` decodes as `lea r8, [rip + 0x3b07a2b]`. Adding the signed displacement `61897259` to the next instruction VA `0x297c3dd` yields `0x6483e08`. The decode from the start of FDE range `[0x297bfa0, 0x297c428)` reaches that instruction boundary. The FDE itself is at `0x115e78c`.

At `0x6483e08` (file offset `0x6481e08`), an `R_X86_64_RELATIVE` relocation points to `0x433bb6` in `.rodata`. The next 16 bytes, `1f000000000000001d0000001d000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 29 and 29. The string's normalized suffix matches `l1/dex_registry/perp_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x297c0b1` is `0x297c3be` and the fallthrough is `0x297c0b7`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rbp, qword ptr [r13 + 0x4640]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297c0aa` | `493bad40460000` | `cmp rbp, qword ptr [r13 + 0x4640]` |
| `0x297c0b1` | `0f8307030000` | `jae 0x297c3be` |
| `0x297c3be` | `66c78424800000005601` | `mov word ptr [rsp + 0x80], 0x156` |
| `0x297c3c8` | `488d3d2bd2e4fd` | `lea rdi, [rip - 0x21b2dd5]` |
| `0x297c3cf` | `488d0d6a7db003` | `lea rcx, [rip + 0x3b07d6a]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 62272176 added to `0x297c3f0` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297c3dd` | `488d942480000000` | `lea rdx, [rsp + 0x80]` |
| `0x297c3e5` | `be2b000000` | `mov esi, 0x2b` |
| `0x297c3ea` | `ff15b032b603` | `call qword ptr [rip + 0x3b632b0]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483e08 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x297bfa0 --stop-address=0x297c3f0 "$target"
od -An -tx1 -j 105389584 -N 16 "$target"
objdump -s -j .rodata --start-address=0x433bb6 --stop-address=0x433bd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d052c7ab003`), re-decoding lands at `0x6483e09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 29, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
