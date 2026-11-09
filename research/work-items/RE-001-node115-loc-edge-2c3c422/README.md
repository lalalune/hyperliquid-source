# RE-001: map node #115 l1/exchange/impl_abstraction.rs:279 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_abstraction.rs` as an embedded path. At ELF VA `0x2c3c422` (file offset `0x2c3b422`), `4c8d0d17148103` decodes as `lea r9, [rip + 0x3811417]`. Adding the signed displacement `58790935` to the next instruction VA `0x2c3c429` yields `0x644d840`. The decode from the start of FDE range `[0x2c3c2b0, 0x2c3c7fc)` reaches that instruction boundary. The FDE itself is at `0x118bcf0`.

At `0x644d840` (file offset `0x644b840`), an `R_X86_64_RELATIVE` relocation points to `0x438d15` in `.rodata`. The next 16 bytes, `2300000000000000170100001c000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 279 and 28. The string's normalized suffix matches `l1/exchange/impl_abstraction.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c3c420` is `0x2c3c470` and the fallthrough is `0x2c3c422`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp r13d, 4`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c3c41c` | `4183fd04` | `cmp r13d, 4` |
| `0x2c3c420` | `754e` | `jne 0x2c3c470` |

## Argument flow

The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed call displacement -1786047 added to `0x2c3c43f` gives `0x2a88380`. The target's FDE at `0xd7b26c` describes `[0x2a88380, 0x2a88641)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c3c429` | `4c89ff` | `mov rdi, r15` |
| `0x2c3c42c` | `4c89e6` | `mov rsi, r12` |
| `0x2c3c42f` | `4c89f2` | `mov rdx, r14` |
| `0x2c3c432` | `4889e9` | `mov rcx, rbp` |
| `0x2c3c435` | `4c8b442420` | `mov r8, qword ptr [rsp + 0x20]` |
| `0x2c3c43a` | `e841bfe4ff` | `call 0x2a88380` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d840 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c3c2b0 --stop-address=0x2c3c43f "$target"
od -An -tx1 -j 105166920 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438d15 --stop-address=0x438d38 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d18148103`), re-decoding lands at `0x644d841`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 279, column 28. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
