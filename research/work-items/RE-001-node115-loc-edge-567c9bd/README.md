# RE-001: map node #115 l1/action/user_outcome.rs:55 conditional call edge

- Component allocation: `action-wire`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/action/user_outcome.rs` as an embedded path. At ELF VA `0x567c9bd` (file offset `0x567b9bd`), `488d0d7cf1e200` decodes as `lea rcx, [rip + 0xe2f17c]`. Adding the signed displacement `14872956` to the next instruction VA `0x567c9c4` yields `0x64abb40`. The decode from the start of FDE range `[0x567c830, 0x567d21d)` reaches that instruction boundary. The FDE itself is at `0xf8e230`.

At `0x64abb40` (file offset `0x64a9b40`), an `R_X86_64_RELATIVE` relocation points to `0x43f111` in `.rodata`. The next 16 bytes, `1d000000000000003700000038000000`, decode as a little-endian 64-bit length of 29 and two 32-bit values, 55 and 56. The string's normalized suffix matches `l1/action/user_outcome.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x567c9b7` is `0x567cf1c` and the fallthrough is `0x567c9bd`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [r15 + 0x18], 0x65`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x567c9b2` | `49837f1865` | `cmp qword ptr [r15 + 0x18], 0x65` |
| `0x567c9b7` | `0f835f050000` | `jae 0x567cf1c` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 15114254 added to `0x567c9d2` gives the relocation slot `0x64e69e0`. Its symbol-zero RELATIVE addend is `0x3c068c0`. The target's FDE at `0xe504d0` describes `[0x3c068c0, 0x3c0697f)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x567c9c4` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x567c9c9` | `4889de` | `mov rsi, rbx` |
| `0x567c9cc` | `ff150ea0e600` | `call qword ptr [rip + 0xe6a00e]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64abb40 '
readelf -rW "$target" | grep -i '0*64e69e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x567c830 --stop-address=0x567c9d2 "$target"
od -An -tx1 -j 105552712 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43f111 --stop-address=0x43f12e "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d7df1e200`), re-decoding lands at `0x64abb41`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 55, column 56. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
