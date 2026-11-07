# RE-001: map node #115 l1/exchange/impl_outcome_deploy.rs:221 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_outcome_deploy.rs` as an embedded path. At ELF VA `0x55d0e4d` (file offset `0x55cfe4d`), `488d0d5497ed00` decodes as `lea rcx, [rip + 0xed9754]`. Adding the signed displacement `15570772` to the next instruction VA `0x55d0e54` yields `0x64aa5a8`. The decode from the start of FDE range `[0x55cfe90, 0x55d1ff0)` reaches that instruction boundary. The FDE itself is at `0x135db80`.

At `0x64aa5a8` (file offset `0x64a85a8`), an `R_X86_64_RELATIVE` relocation points to `0x432caf` in `.rodata`. The next 16 bytes, `2600000000000000dd00000027000000`, decode as a little-endian 64-bit length of 38 and two 32-bit values, 221 and 39. The string's normalized suffix matches `l1/exchange/impl_outcome_deploy.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x55d0e42` is `0x55d12c4` and the fallthrough is `0x55d0e48`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 0x1a2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55d0e3d` | `3da2010000` | `cmp eax, 0x1a2` |
| `0x55d0e42` | `0f857c040000` | `jne 0x55d12c4` |
| `0x55d0e48` | `488b542418` | `mov rdx, qword ptr [rsp + 0x18]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 15822622 added to `0x55d0e62` gives the relocation slot `0x64e7d80`. Its symbol-zero RELATIVE addend is `0x3c06b50`. The target's FDE at `0xe50558` describes `[0x3c06b50, 0x3c06c08)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55d0e54` | `488d7c2410` | `lea rdi, [rsp + 0x10]` |
| `0x55d0e59` | `4c89e6` | `mov rsi, r12` |
| `0x55d0e5c` | `ff151e6ff100` | `call qword ptr [rip + 0xf16f1e]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa5a8 '
readelf -rW "$target" | grep -i '0*64e7d80 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55cfe90 --stop-address=0x55d0e62 "$target"
od -An -tx1 -j 105547184 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432caf --stop-address=0x432cd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d5597ed00`), re-decoding lands at `0x64aa5a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 221, column 39. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
