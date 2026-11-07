# RE-001: map node #115 l1/abci/hash_signature_tracker.rs:123 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/hash_signature_tracker.rs` as an embedded path. At ELF VA `0x5afb20b` (file offset `0x5afa20b`), `488d3566169c00` decodes as `lea rsi, [rip + 0x9c1666]`. Adding the signed displacement `10229350` to the next instruction VA `0x5afb212` yields `0x64bc878`. The decode from the start of FDE range `[0x5afadd0, 0x5afb3a3)` reaches that instruction boundary. The FDE itself is at `0x13b2a44`.

At `0x64bc878` (file offset `0x64ba878`), an `R_X86_64_RELATIVE` relocation points to `0x44d8e1` in `.rodata`. The next 16 bytes, `25000000000000007b00000020000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 123 and 32. The string's normalized suffix matches `l1/abci/hash_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5afb209` is `0x5afb21d` and the fallthrough is `0x5afb20b`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 0xffff`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afb204` | `3dffff0000` | `cmp eax, 0xffff` |
| `0x5afb209` | `7412` | `je 0x5afb21d` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 10394763 added to `0x5afb21d` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afb212` | `bf0b000000` | `mov edi, 0xb` |
| `0x5afb217` | `ff158b9c9e00` | `call qword ptr [rip + 0x9e9c8b]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64bc878 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5afadd0 --stop-address=0x5afb21d "$target"
od -An -tx1 -j 105621632 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d8e1 --stop-address=0x44d906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3567169c00`), re-decoding lands at `0x64bc879`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 123, column 32. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
