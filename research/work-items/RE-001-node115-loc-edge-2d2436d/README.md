# RE-001: map node #115 l1/abci/engine.rs:262 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/engine.rs` as an embedded path. At ELF VA `0x2d2436d` (file offset `0x2d2336d`), `4c8d0dbccd7203` decodes as `lea r9, [rip + 0x372cdbc]`. Adding the signed displacement `57855420` to the next instruction VA `0x2d24374` yields `0x6451130`. The decode from the start of FDE range `[0x2d23610, 0x2d2561c)` reaches that instruction boundary. The FDE itself is at `0x119bce8`.

At `0x6451130` (file offset `0x644f130`), an `R_X86_64_RELATIVE` relocation points to `0x434ab0` in `.rodata`. The next 16 bytes, `15000000000000000601000011000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 262 and 17. The string's normalized suffix matches `l1/abci/engine.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2d24367` is `0x2d24ed1` and the fallthrough is `0x2d2436d`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rax, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d24364` | `4839c8` | `cmp rax, rcx` |
| `0x2d24367` | `0f84640b0000` | `je 0x2d24ed1` |

## Argument flow

The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 58448602 added to `0x2d2438e` gives the relocation slot `0x64e1e68`. Its symbol-zero RELATIVE addend is `0x167bbeb`. The target's FDE at `0xcc29d8` describes `[0x167bbeb, 0x167bc20)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d24374` | `488db42490020000` | `lea rsi, [rsp + 0x290]` |
| `0x2d2437c` | `488d9424c0000000` | `lea rdx, [rsp + 0xc0]` |
| `0x2d24384` | `31ff` | `xor edi, edi` |
| `0x2d24386` | `31c9` | `xor ecx, ecx` |
| `0x2d24388` | `ff15dada7b03` | `call qword ptr [rip + 0x37bdada]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6451130 '
readelf -rW "$target" | grep -i '0*64e1e68 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2d23610 --stop-address=0x2d2438e "$target"
od -An -tx1 -j 105181496 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434ab0 --stop-address=0x434ac5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0dbdcd7203`), re-decoding lands at `0x6451131`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 262, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
