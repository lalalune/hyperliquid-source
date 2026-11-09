# RE-001: map node #115 l1/exchange/end_block.rs:194 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/end_block.rs` as an embedded path. At ELF VA `0x5608dcc` (file offset `0x5607dcc`), `488d357d18ea00` decodes as `lea rsi, [rip + 0xea187d]`. Adding the signed displacement `15341693` to the next instruction VA `0x5608dd3` yields `0x64aa650`. The decode from the start of FDE range `[0x5605ee0, 0x5609de8)` reaches that instruction boundary. The FDE itself is at `0x135f230`.

At `0x64aa650` (file offset `0x64a8650`), an `R_X86_64_RELATIVE` relocation points to `0x431a94` in `.rodata`. The next 16 bytes, `1c00000000000000c200000020000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 194 and 32. The string's normalized suffix matches `l1/exchange/end_block.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5608dbf` is `0x5608de0` and the fallthrough is `0x5608dc1`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rax + 0x37da], 0`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5608db8` | `80b8da37000000` | `cmp byte ptr [rax + 0x37da], 0` |
| `0x5608dbf` | `751f` | `jne 0x5608de0` |
| `0x5608dc1` | `488b0424` | `mov rax, qword ptr [rsp]` |
| `0x5608dc5` | `c680da37000001` | `mov byte ptr [rax + 0x37da], 1` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 15581384 added to `0x5608de0` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5608dd3` | `b301` | `mov bl, 1` |
| `0x5608dd5` | `bf03000000` | `mov edi, 3` |
| `0x5608dda` | `ff15c8c0ed00` | `call qword ptr [rip + 0xedc0c8]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa650 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5605ee0 --stop-address=0x5608de0 "$target"
od -An -tx1 -j 105547352 -N 16 "$target"
objdump -s -j .rodata --start-address=0x431a94 --stop-address=0x431ab0 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d357e18ea00`), re-decoding lands at `0x64aa651`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 194, column 32. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
