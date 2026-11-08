# RE-001: map node #115 l1/qtys/mod.rs:833 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x46a668c` (file offset `0x46a568c`), `488d351dcfde01` decodes as `lea rsi, [rip + 0x1decf1d]`. Adding the signed displacement `31379229` to the next instruction VA `0x46a6693` yields `0x64935b0`. The decode from the start of FDE range `[0x46a6370, 0x46a685c)` reaches that instruction boundary. The FDE itself is at `0xef3950`.

At `0x64935b0` (file offset `0x64915b0`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000004103000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 833 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x46a6684` is `0x46a670c` and the fallthrough is `0x46a668a`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rbp, rbx`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x46a6681` | `4839dd` | `cmp rbp, rbx` |
| `0x46a6684` | `0f8382000000` | `jae 0x46a670c` |
| `0x46a668a` | `31ff` | `xor edi, edi` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 31713295 added to `0x46a6699` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x46a6693` | `ff150fe8e301` | `call qword ptr [rip + 0x1e3e80f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64935b0 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x46a6370 --stop-address=0x46a6699 "$target"
od -An -tx1 -j 105452984 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d351ecfde01`), re-decoding lands at `0x64935b1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 833, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
