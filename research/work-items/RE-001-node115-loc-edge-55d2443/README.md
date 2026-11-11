# RE-001: map node #115 l1/exchange/impl_outcome_deploy.rs:303 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_outcome_deploy.rs` as an embedded path. At ELF VA `0x55d2443` (file offset `0x55d1443`), `488d0d4681ed00` decodes as `lea rcx, [rip + 0xed8146]`. Adding the signed displacement `15565126` to the next instruction VA `0x55d244a` yields `0x64aa590`. The decode from the start of FDE range `[0x55d1ff0, 0x55d4150)` reaches that instruction boundary. The FDE itself is at `0x135dbd4`.

At `0x64aa590` (file offset `0x64a8590`), an `R_X86_64_RELATIVE` relocation points to `0x432caf` in `.rodata`. The next 16 bytes, `26000000000000002f01000037000000`, decode as a little-endian 64-bit length of 38 and two 32-bit values, 303 and 55. The string's normalized suffix matches `l1/exchange/impl_outcome_deploy.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x55d2435` is `0x55d3101` and the fallthrough is `0x55d243b`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rbp, qword ptr [rax + 0x70]`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55d2431` | `483b6870` | `cmp rbp, qword ptr [rax + 0x70]` |
| `0x55d2435` | `0f85c60c0000` | `jne 0x55d3101` |
| `0x55d243b` | `48898c24e8020000` | `mov qword ptr [rsp + 0x2e8], rcx` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 15816997 added to `0x55d245b` gives the relocation slot `0x64e7d80`. Its symbol-zero RELATIVE addend is `0x3c06b50`. The target's FDE at `0xe50558` describes `[0x3c06b50, 0x3c06c08)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55d244a` | `488d7c2410` | `lea rdi, [rsp + 0x10]` |
| `0x55d244f` | `4c89e6` | `mov rsi, r12` |
| `0x55d2452` | `4889ea` | `mov rdx, rbp` |
| `0x55d2455` | `ff152559f100` | `call qword ptr [rip + 0xf15925]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa590 '
readelf -rW "$target" | grep -i '0*64e7d80 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55d1ff0 --stop-address=0x55d245b "$target"
od -An -tx1 -j 105547160 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432caf --stop-address=0x432cd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d4781ed00`), re-decoding lands at `0x64aa591`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 303, column 55. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
