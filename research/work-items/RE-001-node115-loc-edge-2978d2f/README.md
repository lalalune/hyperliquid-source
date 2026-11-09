# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2978d2f` (file offset `0x2977d2f`), `4c8d05aaa0ac03` decodes as `lea r8, [rip + 0x3aca0aa]`. Adding the signed displacement `61644970` to the next instruction VA `0x2978d36` yields `0x6442de0`. The decode from the start of FDE range `[0x2978cd0, 0x2978dc9)` reaches that instruction boundary. The FDE itself is at `0x115dda4`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2978ce0` is `0x2978da5` and the fallthrough is `0x2978ce6`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2978cde` | `85c0` | `test eax, eax` |
| `0x2978ce0` | `0f85bf000000` | `jne 0x2978da5` |
| `0x2978ce6` | `4889f3` | `mov rbx, rsi` |
| `0x2978ce9` | `4989fe` | `mov r14, rdi` |
| `0x2978cec` | `488b4618` | `mov rax, qword ptr [rsi + 0x18]` |
| `0x2978cf0` | `488b4e10` | `mov rcx, qword ptr [rsi + 0x10]` |
| `0x2978cf4` | `48894c2410` | `mov qword ptr [rsp + 0x10], rcx` |
| `0x2978cf9` | `0f1006` | `movups xmm0, xmmword ptr [rsi]` |
| `0x2978cfc` | `0f290424` | `movaps xmmword ptr [rsp], xmm0` |
| `0x2978d00` | `488b30` | `mov rsi, qword ptr [rax]` |
| `0x2978d03` | `488d4610` | `lea rax, [rsi + 0x10]` |
| `0x2978d07` | `0f104320` | `movups xmm0, xmmword ptr [rbx + 0x20]` |
| `0x2978d0b` | `0f11442430` | `movups xmmword ptr [rsp + 0x30], xmm0` |
| `0x2978d10` | `48c744242800000000` | `mov qword ptr [rsp + 0x28], 0` |
| `0x2978d19` | `4881c640010000` | `add rsi, 0x140` |
| `0x2978d20` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x2978d25` | `488d442428` | `lea rax, [rsp + 0x28]` |
| `0x2978d2a` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement 248091 added to `0x2978d45` gives `0x29b5660`. The target's FDE at `0x1161578` describes `[0x29b5660, 0x29b601d)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2978d36` | `488d7c2440` | `lea rdi, [rsp + 0x40]` |
| `0x2978d3b` | `4889e2` | `mov rdx, rsp` |
| `0x2978d3e` | `31c9` | `xor ecx, ecx` |
| `0x2978d40` | `e81bc90300` | `call 0x29b5660` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2978cd0 --stop-address=0x2978d45 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05aba0ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
