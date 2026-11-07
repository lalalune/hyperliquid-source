# RE-001: map node #115 l1/action/vote_global.rs:1504 conditional call edge

- Component allocation: `action-wire`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/action/vote_global.rs` as an embedded path. At ELF VA `0x28d4683` (file offset `0x28d3683`), `488d35bec0b603` decodes as `lea rsi, [rip + 0x3b6c0be]`. Adding the signed displacement `62308542` to the next instruction VA `0x28d468a` yields `0x6440748`. The decode from the start of FDE range `[0x28cd7a0, 0x28d8ac4)` reaches that instruction boundary. The FDE itself is at `0x11568b8`.

At `0x6440748` (file offset `0x643e748`), an `R_X86_64_RELATIVE` relocation points to `0x435952` in `.rodata`. The next 16 bytes, `1c00000000000000e005000028000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 1504 and 40. The string's normalized suffix matches `l1/action/vote_global.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x28d467d` is `0x28d5896` and the fallthrough is `0x28d4683`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp cl, 1`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x28d467a` | `80f901` | `cmp cl, 1` |
| `0x28d467d` | `0f8513120000` | `jne 0x28d5896` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 62982163 added to `0x28d4695` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x28d468a` | `bf03000000` | `mov edi, 3` |
| `0x28d468f` | `ff151308c103` | `call qword ptr [rip + 0x3c10813]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6440748 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x28cd7a0 --stop-address=0x28d4695 "$target"
od -An -tx1 -j 105113424 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435952 --stop-address=0x43596e "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35bfc0b603`), re-decoding lands at `0x6440749`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1504, column 40. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
