# RE-001: map node #115 base/lu.rs:75 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x5a2f8e4` (file offset `0x5a2e8e4`), `488d0dbd88a800` decodes as `lea rcx, [rip + 0xa888bd]`. Adding the signed displacement `11045053` to the next instruction VA `0x5a2f8eb` yields `0x64b81a8`. The decode from the start of FDE range `[0x5a2f760, 0x5a2fa70)` reaches that instruction boundary. The FDE itself is at `0x13a1db4`.

At `0x64b81a8` (file offset `0x64b61a8`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e000000000000004b00000005000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 75 and 5. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5a2f8d8` is `0x5a2f9f5` and the fallthrough is `0x5a2f8de`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp edi, 0x43f`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a2f8d2` | `81ff3f040000` | `cmp edi, 0x43f` |
| `0x5a2f8d8` | `0f8317010000` | `jae 0x5a2f9f5` |
| `0x5a2f8de` | `80c1cd` | `add cl, 0xcd` |
| `0x5a2f8e1` | `48d3e6` | `shl rsi, cl` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 11213482 added to `0x5a2f8f6` gives the relocation slot `0x64e13a0`. Its symbol-zero RELATIVE addend is `0x5cf2150`. The target's FDE at `0x13d4374` describes `[0x5cf2150, 0x5cf22e9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a2f8eb` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x5a2f8f0` | `ff15aa1aab00` | `call qword ptr [rip + 0xab1aaa]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b81a8 '
readelf -rW "$target" | grep -i '0*64e13a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a2f760 --stop-address=0x5a2f8f6 "$target"
od -An -tx1 -j 105603504 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dbe88a800`), re-decoding lands at `0x64b81a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 75, column 5. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
