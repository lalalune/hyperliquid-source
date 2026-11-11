# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:438 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x5b737e2` (file offset `0x5b727e2`), `488d1527d39300` decodes as `lea rdx, [rip + 0x93d327]`. Adding the signed displacement `9687847` to the next instruction VA `0x5b737e9` yields `0x64b0b10`. The decode from the start of FDE range `[0x5b73430, 0x5b7383e)` reaches that instruction boundary. The FDE itself is at `0x13bfad4`.

At `0x64b0b10` (file offset `0x64aeb10`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `2500000000000000b601000012000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 438 and 18. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5b735cd` is `0x5b737c4` and the fallthrough is `0x5b735d3`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdi, rsi`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5b735ca` | `4839f7` | `cmp rdi, rsi` |
| `0x5b735cd` | `0f83f1010000` | `jae 0x5b737c4` |
| `0x5b737c4` | `4969c410270000` | `imul rax, r12, 0x2710` |
| `0x5b737cb` | `4901c6` | `add r14, rax` |
| `0x5b737ce` | `4c89f0` | `mov rax, r14` |
| `0x5b737d1` | `48f7e5` | `mul rbp` |
| `0x5b737d4` | `48c1ea0b` | `shr rdx, 0xb` |
| `0x5b737d8` | `4869faf0d8ffff` | `imul rdi, rdx, -0x2710` |
| `0x5b737df` | `4c01f7` | `add rdi, r14` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 9879089 added to `0x5b737ef` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5b737e9` | `ff1531be9600` | `call qword ptr [rip + 0x96be31]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0b10 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5b73430 --stop-address=0x5b737ef "$target"
od -An -tx1 -j 105573144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1528d39300`), re-decoding lands at `0x64b0b11`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 438, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
