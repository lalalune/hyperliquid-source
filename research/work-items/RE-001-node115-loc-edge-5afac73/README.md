# RE-001: map node #115 l1/abci/hash_signature_tracker.rs:174 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/abci/hash_signature_tracker.rs` as an embedded path. At ELF VA `0x5afac73` (file offset `0x5af9c73`), `4c8d05b61b9c00` decodes as `lea r8, [rip + 0x9c1bb6]`. Adding the signed displacement `10230710` to the next instruction VA `0x5afac7a` yields `0x64bc830`. The decode from the start of FDE range `[0x5afa7f0, 0x5afadc3)` reaches that instruction boundary. The FDE itself is at `0x13b2998`.

At `0x64bc830` (file offset `0x64ba830`), an `R_X86_64_RELATIVE` relocation points to `0x44d8e1` in `.rodata`. The next 16 bytes, `2500000000000000ae0000002a000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 174 and 42. The string's normalized suffix matches `l1/abci/hash_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x5afac5d` establish a local edge into the argument setup. The taken target is `0x5afad3f` and the fallthrough is `0x5afac63`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test eax, eax`. The recorded edge reaches the load when the `jne` predicate (`ZF = 0`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afac5b` | `85c0` | `test eax, eax` |
| `0x5afac5d` | `0f85dc000000` | `jne 0x5afad3f` |
| `0x5afac63` | `498d7660` | `lea rsi, [r14 + 0x60]` |
| `0x5afac67` | `488b842430020000` | `mov rax, qword ptr [rsp + 0x230]` |
| `0x5afac6f` | `488d4860` | `lea rcx, [rax + 0x60]` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -13879975 added to `0x5afac87` gives `0x4dbe1e0`. The target's FDE at `0x12f8030` describes `[0x4dbe1e0, 0x4dbe6ad)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afac7a` | `488dbc24d8000000` | `lea rdi, [rsp + 0xd8]` |
| `0x5afac82` | `e859352cff` | `call 0x4dbe1e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64bc830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5afa7f0 --stop-address=0x5afac87 "$target"
od -An -tx1 -j 105621560 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d8e1 --stop-address=0x44d906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05b71b9c00`), re-decoding lands at `0x64bc831`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 174, column 42. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
