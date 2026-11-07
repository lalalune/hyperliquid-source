# RE-001: map node #115 l1/abci/engine.rs:262 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/engine.rs` as an embedded path. At ELF VA `0x5a06e58` (file offset `0x5a05e58`), `4c8d0d5111ab00` decodes as `lea r9, [rip + 0xab1151]`. Adding the signed displacement `11211089` to the next instruction VA `0x5a06e5f` yields `0x64b7fb0`. The decode from the start of FDE range `[0x5a06600, 0x5a07eb6)` reaches that instruction boundary. The FDE itself is at `0x13a0ac0`.

At `0x64b7fb0` (file offset `0x64b5fb0`), an `R_X86_64_RELATIVE` relocation points to `0x434ab0` in `.rodata`. The next 16 bytes, `15000000000000000601000011000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 262 and 17. The string's normalized suffix matches `l1/abci/engine.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5a06e52` is `0x5a077d9` and the fallthrough is `0x5a06e58`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rax, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a06e4f` | `4839c8` | `cmp rax, rcx` |
| `0x5a06e52` | `0f8481090000` | `je 0x5a077d9` |

## Argument flow

The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 11382767 added to `0x5a06e79` gives the relocation slot `0x64e1e68`. Its symbol-zero RELATIVE addend is `0x167bbeb`. The target's FDE at `0xcc29d8` describes `[0x167bbeb, 0x167bc20)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a06e5f` | `488db42440020000` | `lea rsi, [rsp + 0x240]` |
| `0x5a06e67` | `488d9424a8000000` | `lea rdx, [rsp + 0xa8]` |
| `0x5a06e6f` | `31ff` | `xor edi, edi` |
| `0x5a06e71` | `31c9` | `xor ecx, ecx` |
| `0x5a06e73` | `ff15efafad00` | `call qword ptr [rip + 0xadafef]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b7fb0 '
readelf -rW "$target" | grep -i '0*64e1e68 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a06600 --stop-address=0x5a06e79 "$target"
od -An -tx1 -j 105603000 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434ab0 --stop-address=0x434ac5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d5211ab00`), re-decoding lands at `0x64b7fb1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 262, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
