# RE-001: map node #115 evm_rpc/method_router.rs:70 conditional call edge

- Component allocation: `evm-rpc`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `evm_rpc/method_router.rs` as an embedded path. At ELF VA `0x2e3830a` (file offset `0x2e3730a`), `4c8d05dfaa6103` decodes as `lea r8, [rip + 0x361aadf]`. Adding the signed displacement `56732383` to the next instruction VA `0x2e38311` yields `0x6452df0`. The decode from the start of FDE range `[0x2e375a0, 0x2e3863e)` reaches that instruction boundary. The FDE itself is at `0x11b2fc0`.

At `0x6452df0` (file offset `0x6450df0`), an `R_X86_64_RELATIVE` relocation points to `0x444dae` in `.rodata`. The next 16 bytes, `1c000000000000004600000038000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 70 and 56. The string's normalized suffix matches `evm_rpc/method_router.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2e37e19` is `0x2e382d9` and the fallthrough is `0x2e37e1f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp ebp, 3`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e37e16` | `83fd03` | `cmp ebp, 3` |
| `0x2e37e19` | `0f85ba040000` | `jne 0x2e382d9` |
| `0x2e382d9` | `4889ac24f8000000` | `mov qword ptr [rsp + 0xf8], rbp` |
| `0x2e382e1` | `660f6f0424` | `movdqa xmm0, xmmword ptr [rsp]` |
| `0x2e382e6` | `f30f7f842400010000` | `movdqu xmmword ptr [rsp + 0x100], xmm0` |
| `0x2e382ef` | `488b442410` | `mov rax, qword ptr [rsp + 0x10]` |
| `0x2e382f4` | `4889842410010000` | `mov qword ptr [rsp + 0x110], rax` |
| `0x2e382fc` | `488d3dbfeb7dfd` | `lea rdi, [rip - 0x2821441]` |
| `0x2e38303` | `488d0d36976103` | `lea rcx, [rip + 0x3619736]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 57308028 added to `0x2e38324` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e38311` | `488d9424f8000000` | `lea rdx, [rsp + 0xf8]` |
| `0x2e38319` | `be2b000000` | `mov esi, 0x2b` |
| `0x2e3831e` | `ff157c736a03` | `call qword ptr [rip + 0x36a737c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6452df0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2e375a0 --stop-address=0x2e38324 "$target"
od -An -tx1 -j 105188856 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444dae --stop-address=0x444dca "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05e0aa6103`), re-decoding lands at `0x6452df1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 70, column 56. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
