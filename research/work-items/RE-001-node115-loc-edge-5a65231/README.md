# RE-001: map node #115 node/evm_kvs.rs:117 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/evm_kvs.rs` as an embedded path. At ELF VA `0x5a65231` (file offset `0x5a64231`), `488d0d583aa500` decodes as `lea rcx, [rip + 0xa53a58]`. Adding the signed displacement `10828376` to the next instruction VA `0x5a65238` yields `0x64b8c90`. The decode from the start of FDE range `[0x5a64aa0, 0x5a69c05)` reaches that instruction boundary. The FDE itself is at `0x13a9d84`.

At `0x64b8c90` (file offset `0x64b6c90`), an `R_X86_64_RELATIVE` relocation points to `0x4432b3` in `.rodata`. The next 16 bytes, `13000000000000007500000009000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 117 and 9. The string's normalized suffix matches `node/evm_kvs.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5a6519c` is `0x5a652a9` and the fallthrough is `0x5a651a2`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a6519a` | `84c0` | `test al, al` |
| `0x5a6519c` | `0f8407010000` | `je 0x5a652a9` |
| `0x5a651a2` | `c684247501000000` | `mov byte ptr [rsp + 0x175], 0` |
| `0x5a651aa` | `c784247101000000000000` | `mov dword ptr [rsp + 0x171], 0` |
| `0x5a651b5` | `48c784246001000000000000` | `mov qword ptr [rsp + 0x160], 0` |
| `0x5a651c1` | `c684247001000001` | `mov byte ptr [rsp + 0x170], 1` |
| `0x5a651c9` | `488d05985fedfa` | `lea rax, [rip - 0x512a068]` |
| `0x5a651d0` | `48898424b0020000` | `mov qword ptr [rsp + 0x2b0], rax` |
| `0x5a651d8` | `48c78424b802000069000000` | `mov qword ptr [rsp + 0x2b8], 0x69` |
| `0x5a651e4` | `4c89b42490000000` | `mov qword ptr [rsp + 0x90], r14` |
| `0x5a651ec` | `488d8424b0020000` | `lea rax, [rsp + 0x2b0]` |
| `0x5a651f4` | `4889842470030000` | `mov qword ptr [rsp + 0x370], rax` |
| `0x5a651fc` | `488d051d50dcff` | `lea rax, [rip - 0x23afe3]` |
| `0x5a65203` | `4889842478030000` | `mov qword ptr [rsp + 0x378], rax` |
| `0x5a6520b` | `488d842490000000` | `lea rax, [rsp + 0x90]` |
| `0x5a65213` | `4889842480030000` | `mov qword ptr [rsp + 0x380], rax` |
| `0x5a6521b` | `488d057e4cdcff` | `lea rax, [rip - 0x23b382]` |
| `0x5a65222` | `4889842488030000` | `mov qword ptr [rsp + 0x388], rax` |
| `0x5a6522a` | `488d358d879efa` | `lea rsi, [rip - 0x5617873]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 10991818 added to `0x5a6524e` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a65238` | `488dbc2460010000` | `lea rdi, [rsp + 0x160]` |
| `0x5a65240` | `488d942470030000` | `lea rdx, [rsp + 0x370]` |
| `0x5a65248` | `ff15cab8a700` | `call qword ptr [rip + 0xa7b8ca]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8c90 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a64aa0 --stop-address=0x5a6524e "$target"
od -An -tx1 -j 105606296 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4432b3 --stop-address=0x4432c6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d593aa500`), re-decoding lands at `0x64b8c91`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 117, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
