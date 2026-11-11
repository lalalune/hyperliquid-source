# RE-001: map node #115 info_server/abci_state_info_handler.rs:82 conditional call edge

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x2978447` (file offset `0x2977447`), `4c8d0592a9ac03` decodes as `lea r8, [rip + 0x3aca992]`. Adding the signed displacement `61647250` to the next instruction VA `0x297844e` yields `0x6442de0`. The decode from the start of FDE range `[0x29783f0, 0x29784a1)` reaches that instruction boundary. The FDE itself is at `0x115db90`.

At `0x6442de0` (file offset `0x6440de0`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a000000000000005200000010000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 82 and 16. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x29783fd` is `0x297847d` and the fallthrough is `0x29783ff`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29783fb` | `85c0` | `test eax, eax` |
| `0x29783fd` | `757e` | `jne 0x297847d` |
| `0x29783ff` | `4889f3` | `mov rbx, rsi` |
| `0x2978402` | `4989fe` | `mov r14, rdi` |
| `0x2978405` | `488b06` | `mov rax, qword ptr [rsi]` |
| `0x2978408` | `8b4e28` | `mov ecx, dword ptr [rsi + 0x28]` |
| `0x297840b` | `894c2450` | `mov dword ptr [rsp + 0x50], ecx` |
| `0x297840f` | `0f104618` | `movups xmm0, xmmword ptr [rsi + 0x18]` |
| `0x2978413` | `0f11442440` | `movups xmmword ptr [rsp + 0x40], xmm0` |
| `0x2978418` | `488b30` | `mov rsi, qword ptr [rax]` |
| `0x297841b` | `488d4610` | `lea rax, [rsi + 0x10]` |
| `0x297841f` | `0f104308` | `movups xmm0, xmmword ptr [rbx + 8]` |
| `0x2978423` | `0f11442420` | `movups xmmword ptr [rsp + 0x20], xmm0` |
| `0x2978428` | `48c744241800000000` | `mov qword ptr [rsp + 0x18], 0` |
| `0x2978431` | `4881c640010000` | `add rsi, 0x140` |
| `0x2978438` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x297843d` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x2978442` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement 372755 added to `0x297845d` gives `0x29d3470`. The target's FDE at `0x11626e8` describes `[0x29d3470, 0x29d3dd8)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297844e` | `4889e7` | `mov rdi, rsp` |
| `0x2978451` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x2978456` | `31c9` | `xor ecx, ecx` |
| `0x2978458` | `e813b00500` | `call 0x29d3470` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6442de0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x29783f0 --stop-address=0x297845d "$target"
od -An -tx1 -j 105123304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0593a9ac03`), re-decoding lands at `0x6442de1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 82, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
