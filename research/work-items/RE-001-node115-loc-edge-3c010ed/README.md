# RE-001: map node #115 l1/qtys/impl_wei.rs:6 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/impl_wei.rs` as an embedded path. At ELF VA `0x3c010ed` (file offset `0x3c000ed`), `488d3584638802` decodes as `lea rsi, [rip + 0x2886384]`. Adding the signed displacement `42492804` to the next instruction VA `0x3c010f4` yields `0x6487478`. The decode from the start of FDE range `[0x3c00da0, 0x3c01184)` reaches that instruction boundary. The FDE itself is at `0xe4ff1c`.

At `0x6487478` (file offset `0x6485478`), an `R_X86_64_RELATIVE` relocation points to `0x43f393` in `.rodata`. The next 16 bytes, `17000000000000000600000001000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 6 and 1. The string's normalized suffix matches `l1/qtys/impl_wei.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3c010eb` is `0x3c01106` and the fallthrough is `0x3c010ed`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp r15, rax`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c010e8` | `4939c7` | `cmp r15, rax` |
| `0x3c010eb` | `7319` | `jae 0x3c01106` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 42876329 added to `0x3c010ff` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c010f4` | `4531ff` | `xor r15d, r15d` |
| `0x3c010f7` | `31ff` | `xor edi, edi` |
| `0x3c010f9` | `ff15a93d8e02` | `call qword ptr [rip + 0x28e3da9]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6487478 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3c00da0 --stop-address=0x3c010ff "$target"
od -An -tx1 -j 105403520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43f393 --stop-address=0x43f3aa "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3585638802`), re-decoding lands at `0x6487479`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 6, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
