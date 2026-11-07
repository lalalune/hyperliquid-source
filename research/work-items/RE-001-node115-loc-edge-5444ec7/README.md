# RE-001: map node #115 node/node.rs:1023 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/node.rs` as an embedded path. At ELF VA `0x5444ec7` (file offset `0x5443ec7`), `4c8d0d12610601` decodes as `lea r9, [rip + 0x1066112]`. Adding the signed displacement `17195282` to the next instruction VA `0x5444ece` yields `0x64aafe0`. The decode from the start of FDE range `[0x5444cb0, 0x5444f9a)` reaches that instruction boundary. The FDE itself is at `0x1350084`.

At `0x64aafe0` (file offset `0x64a8fe0`), an `R_X86_64_RELATIVE` relocation points to `0x44aca3` in `.rodata`. The next 16 bytes, `1000000000000000ff03000015000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 1023 and 21. The string's normalized suffix matches `node/node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5444d8f` is `0x5444e95` and the fallthrough is `0x5444d95`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 0xffff`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5444d8a` | `3dffff0000` | `cmp eax, 0xffff` |
| `0x5444d8f` | `0f8500010000` | `jne 0x5444e95` |
| `0x5444e95` | `488db42400010000` | `lea rsi, [rsp + 0x100]` |
| `0x5444e9d` | `4889742420` | `mov qword ptr [rsp + 0x20], rsi` |
| `0x5444ea2` | `488d0557632000` | `lea rax, [rip + 0x206357]` |
| `0x5444ea9` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x5444eae` | `488d942420010000` | `lea rdx, [rsp + 0x120]` |
| `0x5444eb6` | `4889542430` | `mov qword ptr [rsp + 0x30], rdx` |
| `0x5444ebb` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x5444ec0` | `488d0d0e6000fb` | `lea rcx, [rip - 0x4ff9ff2]` |

## Argument flow

The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 17460661 added to `0x5444edb` gives the relocation slot `0x64ebc90`. Its symbol-zero RELATIVE addend is `0x5a5d351`. The target's FDE at `0xfc49ac` describes `[0x5a5d351, 0x5a5d384)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5444ece` | `4c8d442420` | `lea r8, [rsp + 0x20]` |
| `0x5444ed3` | `31ff` | `xor edi, edi` |
| `0x5444ed5` | `ff15b56d0a01` | `call qword ptr [rip + 0x10a6db5]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aafe0 '
readelf -rW "$target" | grep -i '0*64ebc90 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5444cb0 --stop-address=0x5444edb "$target"
od -An -tx1 -j 105549800 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44aca3 --stop-address=0x44acb3 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d13610601`), re-decoding lands at `0x64aafe1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 1023, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
