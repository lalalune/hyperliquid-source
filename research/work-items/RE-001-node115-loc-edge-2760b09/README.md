# RE-001: map node #115 l1/abci/hash_signature_tracker.rs:123 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/hash_signature_tracker.rs` as an embedded path. At ELF VA `0x2760b09` (file offset `0x275fb09`), `488d35f8a7cd03` decodes as `lea rsi, [rip + 0x3cda7f8]`. Adding the signed displacement `63809528` to the next instruction VA `0x2760b10` yields `0x643b308`. The decode from the start of FDE range `[0x27606d0, 0x2760bbc)` reaches that instruction boundary. The FDE itself is at `0x1137524`.

At `0x643b308` (file offset `0x6439308`), an `R_X86_64_RELATIVE` relocation points to `0x44d8e1` in `.rodata`. The next 16 bytes, `25000000000000007b00000020000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 123 and 32. The string's normalized suffix matches `l1/abci/hash_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2760b07` is `0x2760b1b` and the fallthrough is `0x2760b09`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 0xffff`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2760b02` | `3dffff0000` | `cmp eax, 0xffff` |
| `0x2760b07` | `7412` | `je 0x2760b1b` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 64504717 added to `0x2760b1b` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2760b10` | `bf0a000000` | `mov edi, 0xa` |
| `0x2760b15` | `ff158d43d803` | `call qword ptr [rip + 0x3d8438d]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*643b308 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x27606d0 --stop-address=0x2760b1b "$target"
od -An -tx1 -j 105091856 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d8e1 --stop-address=0x44d906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35f9a7cd03`), re-decoding lands at `0x643b309`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 123, column 32. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
