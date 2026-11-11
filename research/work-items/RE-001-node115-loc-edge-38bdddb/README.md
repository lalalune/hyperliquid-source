# RE-001: map node #115 l1/spot_meta.rs:590 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/spot_meta.rs` as an embedded path. At ELF VA `0x38bdddb` (file offset `0x38bcddb`), `488d058e06bb02` decodes as `lea rax, [rip + 0x2bb068e]`. Adding the signed displacement `45811342` to the next instruction VA `0x38bdde2` yields `0x646e470`. The decode from the start of FDE range `[0x38bdbe0, 0x38bddee)` reaches that instruction boundary. The FDE itself is at `0xe33568`.

At `0x646e470` (file offset `0x646c470`), an `R_X86_64_RELATIVE` relocation points to `0x432b6f` in `.rodata`. The next 16 bytes, `13000000000000004e02000019000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 590 and 25. The string's normalized suffix matches `l1/spot_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x38bdbf8` is `0x38bdddb` and the fallthrough is `0x38bdbfe`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, rsi`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bdbf5` | `4839f2` | `cmp rdx, rsi` |
| `0x38bdbf8` | `0f83dd010000` | `jae 0x38bdddb` |

## Argument flow

The LEA writes `rax`. The trace follows full-width copies into `rdx`, tracking any intervening register writes. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 46274610 added to `0x38bddee` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bdde2` | `4889d7` | `mov rdi, rdx` |
| `0x38bdde5` | `4889c2` | `mov rdx, rax` |
| `0x38bdde8` | `ff153218c202` | `call qword ptr [rip + 0x2c21832]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e470 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38bdbe0 --stop-address=0x38bddee "$target"
od -An -tx1 -j 105301112 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b6f --stop-address=0x432b82 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d058f06bb02`), re-decoding lands at `0x646e471`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 590, column 25. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
