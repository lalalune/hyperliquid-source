# RE-001: map node #115 node/startup.rs:76 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/startup.rs` as an embedded path. At ELF VA `0x2cbbf41` (file offset `0x2cbaf41`), `4c8d05d8237903` decodes as `lea r8, [rip + 0x37923d8]`. Adding the signed displacement `58270680` to the next instruction VA `0x2cbbf48` yields `0x644e320`. The decode from the start of FDE range `[0x2cbbbe0, 0x2cbfc3f)` reaches that instruction boundary. The FDE itself is at `0x1196944`.

At `0x644e320` (file offset `0x644c320`), an `R_X86_64_RELATIVE` relocation points to `0x438c81` in `.rodata`. The next 16 bytes, `13000000000000004c00000025000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 76 and 37. The string's normalized suffix matches `node/startup.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2cbbec2` is `0x2cbeca9` and the fallthrough is `0x2cbbec8`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rax, qword ptr [rsp + 0x6a0]`. The recorded edge is selected when the `jo` predicate (`OF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cbbeba` | `483b8424a0060000` | `cmp rax, qword ptr [rsp + 0x6a0]` |
| `0x2cbbec2` | `0f80e12d0000` | `jo 0x2cbeca9` |
| `0x2cbbec8` | `488b842400070000` | `mov rax, qword ptr [rsp + 0x700]` |
| `0x2cbbed0` | `48898424a0010000` | `mov qword ptr [rsp + 0x1a0], rax` |
| `0x2cbbed8` | `0f108424f0060000` | `movups xmm0, xmmword ptr [rsp + 0x6f0]` |
| `0x2cbbee0` | `0f29842490010000` | `movaps xmmword ptr [rsp + 0x190], xmm0` |
| `0x2cbbee8` | `0f108424e0060000` | `movups xmm0, xmmword ptr [rsp + 0x6e0]` |
| `0x2cbbef0` | `0f29842480010000` | `movaps xmmword ptr [rsp + 0x180], xmm0` |
| `0x2cbbef8` | `f30f6f8424a0060000` | `movdqu xmm0, xmmword ptr [rsp + 0x6a0]` |
| `0x2cbbf01` | `0f108c24b0060000` | `movups xmm1, xmmword ptr [rsp + 0x6b0]` |
| `0x2cbbf09` | `0f109424c0060000` | `movups xmm2, xmmword ptr [rsp + 0x6c0]` |
| `0x2cbbf11` | `0f109c24d0060000` | `movups xmm3, xmmword ptr [rsp + 0x6d0]` |
| `0x2cbbf19` | `0f299c2470010000` | `movaps xmmword ptr [rsp + 0x170], xmm3` |
| `0x2cbbf21` | `0f29942460010000` | `movaps xmmword ptr [rsp + 0x160], xmm2` |
| `0x2cbbf29` | `0f298c2450010000` | `movaps xmmword ptr [rsp + 0x150], xmm1` |
| `0x2cbbf31` | `660f7f842440010000` | `movdqa xmmword ptr [rsp + 0x140], xmm0` |
| `0x2cbbf3a` | `488d15f83395fd` | `lea rdx, [rip - 0x26acc08]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement -8095010 added to `0x2cbbf62` gives `0x2503a40`. The target's FDE at `0x111cf74` describes `[0x2503a40, 0x250400e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cbbf48` | `488dbc2470210000` | `lea rdi, [rsp + 0x2170]` |
| `0x2cbbf50` | `488db42440010000` | `lea rsi, [rsp + 0x140]` |
| `0x2cbbf58` | `b90c000000` | `mov ecx, 0xc` |
| `0x2cbbf5d` | `e8de7a84ff` | `call 0x2503a40` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644e320 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2cbbbe0 --stop-address=0x2cbbf62 "$target"
od -An -tx1 -j 105169704 -N 16 "$target"
objdump -s -j .rodata --start-address=0x438c81 --stop-address=0x438c94 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05d9237903`), re-decoding lands at `0x644e321`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 76, column 37. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
