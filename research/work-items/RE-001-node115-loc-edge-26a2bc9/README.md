# RE-001: map node #115 l1/abci/state.rs:193 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/state.rs` as an embedded path. At ELF VA `0x26a2bc9` (file offset `0x26a1bc9`), `4c8d05c048d903` decodes as `lea r8, [rip + 0x3d948c0]`. Adding the signed displacement `64571584` to the next instruction VA `0x26a2bd0` yields `0x6437490`. The decode from the start of FDE range `[0x26a2810, 0x26a2c7e)` reaches that instruction boundary. The FDE itself is at `0x112c53c`.

At `0x6437490` (file offset `0x6435490`), an `R_X86_64_RELATIVE` relocation points to `0x443168` in `.rodata`. The next 16 bytes, `1400000000000000c100000038000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 193 and 56. The string's normalized suffix matches `l1/abci/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x26a2b9a` is `0x26a2bac` and the fallthrough is `0x26a2b9c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26a2b97` | `4885f6` | `test rsi, rsi` |
| `0x26a2b9a` | `7410` | `je 0x26a2bac` |
| `0x26a2bac` | `4c89642428` | `mov qword ptr [rsp + 0x28], r12` |
| `0x26a2bb1` | `48895c2430` | `mov qword ptr [rsp + 0x30], rbx` |
| `0x26a2bb6` | `4c89742438` | `mov qword ptr [rsp + 0x38], r14` |
| `0x26a2bbb` | `488d3d5b17f5fd` | `lea rdi, [rip - 0x20ae8a5]` |
| `0x26a2bc2` | `488d0d374ad903` | `lea rcx, [rip + 0x3d94a37]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 65260224 added to `0x26a2be0` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26a2bd0` | `488d542428` | `lea rdx, [rsp + 0x28]` |
| `0x26a2bd5` | `be2b000000` | `mov esi, 0x2b` |
| `0x26a2bda` | `ff15c0cae303` | `call qword ptr [rip + 0x3e3cac0]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6437490 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x26a2810 --stop-address=0x26a2be0 "$target"
od -An -tx1 -j 105075864 -N 16 "$target"
objdump -s -j .rodata --start-address=0x443168 --stop-address=0x44317c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05c148d903`), re-decoding lands at `0x6437491`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 193, column 56. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
