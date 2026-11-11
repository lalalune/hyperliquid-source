# RE-001: map node #115 l1/exchange/exchange.rs:607 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/exchange.rs` as an embedded path. At ELF VA `0x54448c4` (file offset `0x54438c4`), `488d15ad590601` decodes as `lea rdx, [rip + 0x10659ad]`. Adding the signed displacement `17193389` to the next instruction VA `0x54448cb` yields `0x64aa278`. The decode from the start of FDE range `[0x5443930, 0x5444cb0)` reaches that instruction boundary. The FDE itself is at `0x1350030`.

At `0x64aa278` (file offset `0x64a8278`), an `R_X86_64_RELATIVE` relocation points to `0x4318d3` in `.rodata`. The next 16 bytes, `1b000000000000005f02000011000000`, decode as a little-endian 64-bit length of 27 and two 32-bit values, 607 and 17. The string's normalized suffix matches `l1/exchange/exchange.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5444667` is `0x54448bd` and the fallthrough is `0x544466d`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rsi + 0x10f0], rcx`. The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5444660` | `48398ef0100000` | `cmp qword ptr [rsi + 0x10f0], rcx` |
| `0x5444667` | `0f8250020000` | `jb 0x54448bd` |
| `0x54448bd` | `488d3d50524efb` | `lea rdi, [rip - 0x4b1adb0]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 17411674 added to `0x54448d6` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x54448cb` | `be3e000000` | `mov esi, 0x3e` |
| `0x54448d0` | `ff155aae0901` | `call qword ptr [rip + 0x109ae5a]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa278 '
readelf -rW "$target" | grep -i '0*64df730 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5443930 --stop-address=0x54448d6 "$target"
od -An -tx1 -j 105546368 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4318d3 --stop-address=0x4318ee "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15ae590601`), re-decoding lands at `0x64aa279`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 607, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
