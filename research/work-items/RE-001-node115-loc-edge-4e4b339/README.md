# RE-001: map node #115 l1/abci/state.rs:193 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/state.rs` as an embedded path. At ELF VA `0x4e4b339` (file offset `0x4e4a339`), `4c8d05d0266501` decodes as `lea r8, [rip + 0x16526d0]`. Adding the signed displacement `23406288` to the next instruction VA `0x4e4b340` yields `0x649da10`. The decode from the start of FDE range `[0x4e4af80, 0x4e4b3ee)` reaches that instruction boundary. The FDE itself is at `0x1304234`.

At `0x649da10` (file offset `0x649ba10`), an `R_X86_64_RELATIVE` relocation points to `0x443168` in `.rodata`. The next 16 bytes, `1400000000000000c100000038000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 193 and 56. The string's normalized suffix matches `l1/abci/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4e4b30a` is `0x4e4b31c` and the fallthrough is `0x4e4b30c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e4b307` | `4885f6` | `test rsi, rsi` |
| `0x4e4b30a` | `7410` | `je 0x4e4b31c` |
| `0x4e4b31c` | `4c89642428` | `mov qword ptr [rsp + 0x28], r12` |
| `0x4e4b321` | `48895c2430` | `mov qword ptr [rsp + 0x30], rbx` |
| `0x4e4b326` | `4c89742438` | `mov qword ptr [rsp + 0x38], r14` |
| `0x4e4b32b` | `488d3d33d5acfb` | `lea rdi, [rip - 0x4532acd]` |
| `0x4e4b332` | `488d0d7f286501` | `lea rcx, [rip + 0x165287f]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 23675728 added to `0x4e4b350` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e4b340` | `488d542428` | `lea rdx, [rsp + 0x28]` |
| `0x4e4b345` | `be2b000000` | `mov esi, 0x2b` |
| `0x4e4b34a` | `ff1550436901` | `call qword ptr [rip + 0x1694350]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649da10 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4e4af80 --stop-address=0x4e4b350 "$target"
od -An -tx1 -j 105495064 -N 16 "$target"
objdump -s -j .rodata --start-address=0x443168 --stop-address=0x44317c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05d1266501`), re-decoding lands at `0x649da11`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 193, column 56. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
