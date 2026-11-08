# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:433 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x517af22` (file offset `0x5179f22`), `488d15b77b3201` decodes as `lea rdx, [rip + 0x1327bb7]`. Adding the signed displacement `20085687` to the next instruction VA `0x517af29` yields `0x64a2ae0`. The decode from the start of FDE range `[0x517a670, 0x517af4d)` reaches that instruction boundary. The FDE itself is at `0x132785c`.

At `0x64a2ae0` (file offset `0x64a0ae0`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `2500000000000000b101000012000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 433 and 18. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x517aa94` is `0x517af22` and the fallthrough is `0x517aa9a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, rsi`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x517aa91` | `4939f6` | `cmp r14, rsi` |
| `0x517aa94` | `0f8388040000` | `jae 0x517af22` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 20334318 added to `0x517af32` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x517af29` | `4c89f7` | `mov rdi, r14` |
| `0x517af2c` | `ff15ee463601` | `call qword ptr [rip + 0x13646ee]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a2ae0 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x517a670 --stop-address=0x517af32 "$target"
od -An -tx1 -j 105515752 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15b87b3201`), re-decoding lands at `0x64a2ae1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 433, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
