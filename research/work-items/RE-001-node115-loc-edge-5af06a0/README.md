# RE-001: map node #115 l1/books.rs:19 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/books.rs` as an embedded path. At ELF VA `0x5af06a0` (file offset `0x5aef6a0`), `488d3db95f9c00` decodes as `lea rdi, [rip + 0x9c5fb9]`. Adding the signed displacement `10248121` to the next instruction VA `0x5af06a7` yields `0x64b6660`. The decode from the start of FDE range `[0x5af0640, 0x5af06ca)` reaches that instruction boundary. The FDE itself is at `0x13b23d4`.

At `0x64b6660` (file offset `0x64b4660`), an `R_X86_64_RELATIVE` relocation points to `0x44e6b2` in `.rodata`. The next 16 bytes, `0f00000000000000130000002f000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 19 and 47. The string's normalized suffix matches `l1/books.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5af0667` is `0x5af06a0` and the fallthrough is `0x5af0669`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rsi, qword ptr [rdx + 0x4658]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5af0660` | `483bb258460000` | `cmp rsi, qword ptr [rdx + 0x4658]` |
| `0x5af0667` | `7337` | `jae 0x5af06a0` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 10416515 added to `0x5af06ad` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5af06a7` | `ff1583f19e00` | `call qword ptr [rip + 0x9ef183]` |

## Callee identification

The resolved callee selects the diagnostic ``called `Option::unwrap()` on a `None` value``. Its bytes at `0x46e992` are `63616c6c656420604f7074696f6e3a3a756e77726170282960206f6e206120604e6f6e65602076616c7565`. The wrapper's RIP-relative indirect call uses slot `0x64df730`, whose RELATIVE addend is the sink at `0x1680e60`. The wrapper trace and sink FDE are recorded alongside the source-location record.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b6660 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5af0640 --stop-address=0x5af06ad "$target"
objdump -d -M intel --start-address=0x1680c10 --stop-address=0x1680c29 "$target"
objdump -s -j .rodata --start-address=0x46e992 --stop-address=0x46e9bd "$target"
readelf -rW "$target" | grep -i '0*64df730 '
od -An -tx1 -j 105596520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e6b2 --stop-address=0x44e6c1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3dba5f9c00`), re-decoding lands at `0x64b6661`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 19, column 47. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
