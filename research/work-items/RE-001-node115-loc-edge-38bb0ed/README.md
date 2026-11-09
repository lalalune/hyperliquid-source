# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:272 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x38bb0ed` (file offset `0x38ba0ed`), `488d351c33bb02` decodes as `lea rsi, [rip + 0x2bb331c]`. Adding the signed displacement `45822748` to the next instruction VA `0x38bb0f4` yields `0x646e410`. The decode from the start of FDE range `[0x38ba5d0, 0x38bb164)` reaches that instruction boundary. The FDE itself is at `0x121df34`.

At `0x646e410` (file offset `0x646c410`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `25000000000000001001000037000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 272 and 55. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x38bb0eb` is `0x38bb0ff` and the fallthrough is `0x38bb0ed`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test byte ptr [rsp + 0x20], 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bb0e6` | `f644242001` | `test byte ptr [rsp + 0x20], 1` |
| `0x38bb0eb` | `7412` | `je 0x38bb0ff` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 46308777 added to `0x38bb0ff` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bb0f4` | `bf08000000` | `mov edi, 8` |
| `0x38bb0f9` | `ff15a99dc202` | `call qword ptr [rip + 0x2c29da9]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e410 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38ba5d0 --stop-address=0x38bb0ff "$target"
od -An -tx1 -j 105301016 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d351d33bb02`), re-decoding lands at `0x646e411`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 272, column 55. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
