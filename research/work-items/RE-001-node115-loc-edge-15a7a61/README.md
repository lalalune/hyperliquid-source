# RE-001: map node #115 base/slack_alert.rs:65 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/slack_alert.rs` as an embedded path. At ELF VA `0x15a7a61` (file offset `0x15a6a61`), `4c8d05b87fe504` decodes as `lea r8, [rip + 0x4e57fb8]`. Adding the signed displacement `82149304` to the next instruction VA `0x15a7a68` yields `0x63ffa20`. The decode from the start of FDE range `[0x15a6680, 0x15a86ab)` reaches that instruction boundary. The FDE itself is at `0x10553a4`.

At `0x63ffa20` (file offset `0x63fda20`), an `R_X86_64_RELATIVE` relocation points to `0x442f18` in `.rodata`. The next 16 bytes, `1700000000000000410000000a000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 65 and 10. The string's normalized suffix matches `base/slack_alert.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x15a777a` is `0x15a7a4b` and the fallthrough is `0x15a7780`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r14, r14`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15a7777` | `4d85f6` | `test r14, r14` |
| `0x15a777a` | `0f85cb020000` | `jne 0x15a7a4b` |
| `0x15a7a4b` | `4c89b42480020000` | `mov qword ptr [rsp + 0x280], r14` |
| `0x15a7a53` | `488d3de510ecfe` | `lea rdi, [rip - 0x113ef1b]` |
| `0x15a7a5a` | `488d0d7f83e504` | `lea rcx, [rip + 0x4e5837f]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 83065893 added to `0x15a7a7b` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15a7a68` | `488d942480020000` | `lea rdx, [rsp + 0x280]` |
| `0x15a7a70` | `be2b000000` | `mov esi, 0x2b` |
| `0x15a7a75` | `ff15257cf304` | `call qword ptr [rip + 0x4f37c25]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63ffa20 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x15a6680 --stop-address=0x15a7a7b "$target"
od -An -tx1 -j 104847912 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442f18 --stop-address=0x442f2f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05b97fe504`), re-decoding lands at `0x63ffa21`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 65, column 10. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
