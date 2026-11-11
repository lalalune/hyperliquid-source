# RE-001: map node #115 base/log/state.rs:35 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/log/state.rs` as an embedded path. At ELF VA `0x1544c2c` (file offset `0x1543c2c`), `4c8d0df590eb04` decodes as `lea r9, [rip + 0x4eb90f5]`. Adding the signed displacement `82546933` to the next instruction VA `0x1544c33` yields `0x63fdd28`. The decode from the start of FDE range `[0x1544b00, 0x1545388)` reaches that instruction boundary. The FDE itself is at `0x104fb94`.

At `0x63fdd28` (file offset `0x63fbd28`), an `R_X86_64_RELATIVE` relocation points to `0x44b81d` in `.rodata`. The next 16 bytes, `15000000000000002300000011000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 35 and 17. The string's normalized suffix matches `base/log/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1544bf8` is `0x1544eed` and the fallthrough is `0x1544bfe`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1544bf6` | `84c0` | `test al, al` |
| `0x1544bf8` | `0f85ef020000` | `jne 0x1544eed` |
| `0x1544bfe` | `4889ac2420010000` | `mov qword ptr [rsp + 0x120], rbp` |
| `0x1544c06` | `488d05a3dc0000` | `lea rax, [rip + 0xdca3]` |
| `0x1544c0d` | `4889842428010000` | `mov qword ptr [rsp + 0x128], rax` |
| `0x1544c15` | `4c89b42430010000` | `mov qword ptr [rsp + 0x130], r14` |
| `0x1544c1d` | `4889842438010000` | `mov qword ptr [rsp + 0x138], rax` |
| `0x1544c25` | `488d0d300aeffe` | `lea rcx, [rip - 0x110f5d0]` |

## Argument flow

The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 83477239 added to `0x1544c49` gives the relocation slot `0x64e0f40`. Its symbol-zero RELATIVE addend is `0x15e0ef7`. The target's FDE at `0xcbb4e4` describes `[0x15e0ef7, 0x15e0f2a)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1544c33` | `4c8d842420010000` | `lea r8, [rsp + 0x120]` |
| `0x1544c3b` | `31ff` | `xor edi, edi` |
| `0x1544c3d` | `4889ee` | `mov rsi, rbp` |
| `0x1544c40` | `4c89f2` | `mov rdx, r14` |
| `0x1544c43` | `ff15f7c2f904` | `call qword ptr [rip + 0x4f9c2f7]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fdd28 '
readelf -rW "$target" | grep -i '0*64e0f40 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1544b00 --stop-address=0x1544c49 "$target"
od -An -tx1 -j 104840496 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44b81d --stop-address=0x44b832 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0df690eb04`), re-decoding lands at `0x63fdd29`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 35, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
