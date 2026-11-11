# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x297961e` (file offset `0x297861e`), `4c8d05bb97ac03` decodes as `lea r8, [rip + 0x3ac97bb]`. Adding the signed displacement `61642683` to the next instruction VA `0x2979625` yields `0x6442de0`. The decode from the start of FDE range `[0x29795c0, 0x297967f)` reaches that instruction boundary. The FDE itself is at `0x115dfcc`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x29795d0` is `0x297965b` and the fallthrough is `0x29795d6`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29795ce` | `85c0` | `test eax, eax` |
| `0x29795d0` | `0f8585000000` | `jne 0x297965b` |
| `0x29795d6` | `4889f3` | `mov rbx, rsi` |
| `0x29795d9` | `4989fe` | `mov r14, rdi` |
| `0x29795dc` | `488b06` | `mov rax, qword ptr [rsi]` |
| `0x29795df` | `8b4e28` | `mov ecx, dword ptr [rsi + 0x28]` |
| `0x29795e2` | `894c2440` | `mov dword ptr [rsp + 0x40], ecx` |
| `0x29795e6` | `0f104618` | `movups xmm0, xmmword ptr [rsi + 0x18]` |
| `0x29795ea` | `0f11442430` | `movups xmmword ptr [rsp + 0x30], xmm0` |
| `0x29795ef` | `488b30` | `mov rsi, qword ptr [rax]` |
| `0x29795f2` | `488d4610` | `lea rax, [rsi + 0x10]` |
| `0x29795f6` | `0f104308` | `movups xmm0, xmmword ptr [rbx + 8]` |
| `0x29795fa` | `0f11442410` | `movups xmmword ptr [rsp + 0x10], xmm0` |
| `0x29795ff` | `48c744240800000000` | `mov qword ptr [rsp + 8], 0` |
| `0x2979608` | `4881c640010000` | `add rsi, 0x140` |
| `0x297960f` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x2979614` | `488d442408` | `lea rax, [rsp + 8]` |
| `0x2979619` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement 382922 added to `0x2979636` gives `0x29d6e00`. The target's FDE at `0x11628f8` describes `[0x29d6e00, 0x29d7768)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2979625` | `488d7c2448` | `lea rdi, [rsp + 0x48]` |
| `0x297962a` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x297962f` | `31c9` | `xor ecx, ecx` |
| `0x2979631` | `e8cad70500` | `call 0x29d6e00` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x29795c0 --stop-address=0x2979636 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05bc97ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
