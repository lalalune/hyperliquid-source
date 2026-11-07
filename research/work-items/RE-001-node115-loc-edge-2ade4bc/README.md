# RE-001: map node #115 net_utils/async_sleep_retry.rs:32 conditional call edge

- Component allocation: `transport`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `net_utils/async_sleep_retry.rs` as an embedded path. At ELF VA `0x2ade4bc` (file offset `0x2add4bc`), `4c8d0525ca9603` decodes as `lea r8, [rip + 0x396ca25]`. Adding the signed displacement `60213797` to the next instruction VA `0x2ade4c3` yields `0x644aee8`. The decode from the start of FDE range `[0x2adce40, 0x2ae00f8)` reaches that instruction boundary. The FDE itself is at `0x117c254`.

At `0x644aee8` (file offset `0x6448ee8`), an `R_X86_64_RELATIVE` relocation points to `0x436a80` in `.rodata`. The next 16 bytes, `22000000000000002000000026000000`, decode as a little-endian 64-bit length of 34 and two 32-bit values, 32 and 38. The string's normalized suffix matches `net_utils/async_sleep_retry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2add29a` is `0x2ade4a9` and the fallthrough is `0x2add2a0`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, 2`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2add296` | `4983fe02` | `cmp r14, 2` |
| `0x2add29a` | `0f8409120000` | `je 0x2ade4a9` |
| `0x2ade4a9` | `4c896c2420` | `mov qword ptr [rsp + 0x20], r13` |
| `0x2ade4ae` | `488d3d8d70b2fd` | `lea rdi, [rip - 0x24d8f73]` |
| `0x2ade4b5` | `488d0dac8e9603` | `lea rcx, [rip + 0x3968eac]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 60821965 added to `0x2ade4d3` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ade4c3` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x2ade4c8` | `be2b000000` | `mov esi, 0x2b` |
| `0x2ade4cd` | `ff15cd11a003` | `call qword ptr [rip + 0x3a011cd]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644aee8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2adce40 --stop-address=0x2ade4d3 "$target"
od -An -tx1 -j 105156336 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a80 --stop-address=0x436aa2 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0526ca9603`), re-decoding lands at `0x644aee9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 32, column 38. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
