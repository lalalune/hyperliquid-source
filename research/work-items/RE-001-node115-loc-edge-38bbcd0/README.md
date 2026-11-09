# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:335 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x38bbcd0` (file offset `0x38bacd0`), `488d356927bb02` decodes as `lea rsi, [rip + 0x2bb2769]`. Adding the signed displacement `45819753` to the next instruction VA `0x38bbcd7` yields `0x646e440`. The decode from the start of FDE range `[0x38bb870, 0x38bbd6c)` reaches that instruction boundary. The FDE itself is at `0x121dfdc`.

At `0x646e440` (file offset `0x646c440`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `25000000000000004f01000019000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 335 and 25. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x38bbccb` is `0x38bbcdd` and the fallthrough is `0x38bbccd`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp al, 0xc`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bbcc9` | `3c0c` | `cmp al, 0xc` |
| `0x38bbccb` | `7410` | `je 0x38bbcdd` |
| `0x38bbccd` | `0fb6f8` | `movzx edi, al` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 46305739 added to `0x38bbcdd` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bbcd7` | `ff15cb91c202` | `call qword ptr [rip + 0x2c291cb]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e440 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38bb870 --stop-address=0x38bbcdd "$target"
od -An -tx1 -j 105301064 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d356a27bb02`), re-decoding lands at `0x646e441`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 335, column 25. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
