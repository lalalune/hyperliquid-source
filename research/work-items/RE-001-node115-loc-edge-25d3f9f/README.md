# RE-001: map node #115 db/db_home.rs:21 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/db_home.rs` as an embedded path. At ELF VA `0x25d3f9f` (file offset `0x25d2f9f`), `488d0d12eee503` decodes as `lea rcx, [rip + 0x3e5ee12]`. Adding the signed displacement `65400338` to the next instruction VA `0x25d3fa6` yields `0x6432db8`. The decode from the start of FDE range `[0x25d3f20, 0x25d4cab)` reaches that instruction boundary. The FDE itself is at `0x1121fd4`.

At `0x6432db8` (file offset `0x6430db8`), an `R_X86_64_RELATIVE` relocation points to `0x448051` in `.rodata`. The next 16 bytes, `11000000000000001500000018000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 21 and 24. The string's normalized suffix matches `db/db_home.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x25d3f9d` is `0x25d400e` and the fallthrough is `0x25d3f9f`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x25d3f9b` | `84c0` | `test al, al` |
| `0x25d3f9d` | `746f` | `je 0x25d400e` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 66111921 added to `0x25d3fb7` gives the relocation slot `0x64e0968`. Its symbol-zero RELATIVE addend is `0x1501290`. The target's FDE at `0xcb1374` describes `[0x1501290, 0x150135b)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x25d3fa6` | `488d7c2418` | `lea rdi, [rsp + 0x18]` |
| `0x25d3fab` | `4c89ee` | `mov rsi, r13` |
| `0x25d3fae` | `4889ea` | `mov rdx, rbp` |
| `0x25d3fb1` | `ff15b1c9f003` | `call qword ptr [rip + 0x3f0c9b1]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6432db8 '
readelf -rW "$target" | grep -i '0*64e0968 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x25d3f20 --stop-address=0x25d3fb7 "$target"
od -An -tx1 -j 105057728 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448051 --stop-address=0x448062 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d13eee503`), re-decoding lands at `0x6432db9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 21, column 24. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
