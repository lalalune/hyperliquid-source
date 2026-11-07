# RE-001: map node #115 info_server/abci_state_info_handler.rs:156 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2976b43` (file offset `0x2975b43`), `488d0d56b3ac03` decodes as `lea rcx, [rip + 0x3acb356]`. Adding the signed displacement `61649750` to the next instruction VA `0x2976b4a` yields `0x6441ea0`. The decode from the start of FDE range `[0x29738e0, 0x2977559)` reaches that instruction boundary. The FDE itself is at `0x115d9f8`.

At `0x6441ea0` (file offset `0x643fea0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000009c00000015000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 156 and 21. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x29739de` is `0x2976abf` and the fallthrough is `0x29739e4`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp ecx, 0xffff`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29739d8` | `81f9ffff0000` | `cmp ecx, 0xffff` |
| `0x29739de` | `0f85db300000` | `jne 0x2976abf` |
| `0x2976abf` | `4989f4` | `mov r12, rsi` |
| `0x2976ac2` | `488d83b4000000` | `lea rax, [rbx + 0xb4]` |
| `0x2976ac9` | `48c744247000000000` | `mov qword ptr [rsp + 0x70], 0` |
| `0x2976ad2` | `c784248000000000000000` | `mov dword ptr [rsp + 0x80], 0` |
| `0x2976add` | `66c78424840000000000` | `mov word ptr [rsp + 0x84], 0` |
| `0x2976ae7` | `48898424b0010000` | `mov qword ptr [rsp + 0x1b0], rax` |
| `0x2976aef` | `488b0582b4b603` | `mov rax, qword ptr [rip + 0x3b6b482]` |
| `0x2976af6` | `48898424b8010000` | `mov qword ptr [rsp + 0x1b8], rax` |
| `0x2976afe` | `488d056aeeabfd` | `lea rax, [rip - 0x2541196]` |
| `0x2976b05` | `48898424a0010000` | `mov qword ptr [rsp + 0x1a0], rax` |
| `0x2976b0d` | `488d8424b0010000` | `lea rax, [rsp + 0x1b0]` |
| `0x2976b15` | `48898424a8010000` | `mov qword ptr [rsp + 0x1a8], rax` |
| `0x2976b1d` | `488d8424a0010000` | `lea rax, [rsp + 0x1a0]` |
| `0x2976b25` | `48898424c0010000` | `mov qword ptr [rsp + 0x1c0], rax` |
| `0x2976b2d` | `488d05dc9ac8ff` | `lea rax, [rip - 0x376524]` |
| `0x2976b34` | `48898424c8010000` | `mov qword ptr [rsp + 0x1c8], rax` |
| `0x2976b3c` | `488d35144dacfd` | `lea rsi, [rip - 0x253b2ec]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 62300091 added to `0x2976b5d` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2976b4a` | `488d7c2470` | `lea rdi, [rsp + 0x70]` |
| `0x2976b4f` | `488d9424c0010000` | `lea rdx, [rsp + 0x1c0]` |
| `0x2976b57` | `ff15bb9fb603` | `call qword ptr [rip + 0x3b69fbb]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6441ea0 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x29738e0 --stop-address=0x2976b5d "$target"
od -An -tx1 -j 105119400 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d57b3ac03`), re-decoding lands at `0x6441ea1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 156, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
