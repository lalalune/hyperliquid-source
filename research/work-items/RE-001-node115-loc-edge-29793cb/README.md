# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x29793cb` (file offset `0x29783cb`), `4c8d050e9aac03` decodes as `lea r8, [rip + 0x3ac9a0e]`. Adding the signed displacement `61643278` to the next instruction VA `0x29793d2` yields `0x6442de0`. The decode from the start of FDE range `[0x2979370, 0x2979429)` reaches that instruction boundary. The FDE itself is at `0x115df30`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x297937d` is `0x2979405` and the fallthrough is `0x2979383`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297937b` | `85c0` | `test eax, eax` |
| `0x297937d` | `0f8582000000` | `jne 0x2979405` |
| `0x2979383` | `4889f3` | `mov rbx, rsi` |
| `0x2979386` | `4989fe` | `mov r14, rdi` |
| `0x2979389` | `488b06` | `mov rax, qword ptr [rsi]` |
| `0x297938c` | `8b4e28` | `mov ecx, dword ptr [rsi + 0x28]` |
| `0x297938f` | `894c2440` | `mov dword ptr [rsp + 0x40], ecx` |
| `0x2979393` | `0f104618` | `movups xmm0, xmmword ptr [rsi + 0x18]` |
| `0x2979397` | `0f11442430` | `movups xmmword ptr [rsp + 0x30], xmm0` |
| `0x297939c` | `488b30` | `mov rsi, qword ptr [rax]` |
| `0x297939f` | `488d4610` | `lea rax, [rsi + 0x10]` |
| `0x29793a3` | `0f104308` | `movups xmm0, xmmword ptr [rbx + 8]` |
| `0x29793a7` | `0f11442410` | `movups xmmword ptr [rsp + 0x10], xmm0` |
| `0x29793ac` | `48c744240800000000` | `mov qword ptr [rsp + 8], 0` |
| `0x29793b5` | `4881c640010000` | `add rsi, 0x140` |
| `0x29793bc` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x29793c1` | `488d442408` | `lea rax, [rsp + 8]` |
| `0x29793c6` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement 226829 added to `0x29793e3` gives `0x29b09f0`. The target's FDE at `0x11612c0` describes `[0x29b09f0, 0x29b1358)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29793d2` | `488d7c2448` | `lea rdi, [rsp + 0x48]` |
| `0x29793d7` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x29793dc` | `31c9` | `xor ecx, ecx` |
| `0x29793de` | `e80d760300` | `call 0x29b09f0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2979370 --stop-address=0x29793e3 "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d050f9aac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
