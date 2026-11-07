# RE-001: map node #115 l1/abci/hash_signature_tracker.rs:174 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/hash_signature_tracker.rs` as an embedded path. At ELF VA `0x5afa6e4` (file offset `0x5af96e4`), `4c8d0545219c00` decodes as `lea r8, [rip + 0x9c2145]`. Adding the signed displacement `10232133` to the next instruction VA `0x5afa6eb` yields `0x64bc830`. The decode from the start of FDE range `[0x5afa5d0, 0x5afa7ef)` reaches that instruction boundary. The FDE itself is at `0x13b2944`.

At `0x64bc830` (file offset `0x64ba830`), an `R_X86_64_RELATIVE` relocation points to `0x44d8e1` in `.rodata`. The next 16 bytes, `2500000000000000ae0000002a000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 174 and 42. The string's normalized suffix matches `l1/abci/hash_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5afa6cf` is `0x5afa769` and the fallthrough is `0x5afa6d5`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afa6cd` | `85c0` | `test eax, eax` |
| `0x5afa6cf` | `0f8594000000` | `jne 0x5afa769` |
| `0x5afa6d5` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x5afa6da` | `498d7760` | `lea rsi, [r15 + 0x60]` |
| `0x5afa6de` | `4c89ea` | `mov rdx, r13` |
| `0x5afa6e1` | `4c89f1` | `mov rcx, r14` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed call displacement -13878544 added to `0x5afa6f0` gives `0x4dbe1e0`. The target's FDE at `0x12f8030` describes `[0x4dbe1e0, 0x4dbe6ad)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afa6eb` | `e8f03a2cff` | `call 0x4dbe1e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64bc830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5afa5d0 --stop-address=0x5afa6f0 "$target"
od -An -tx1 -j 105621560 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d8e1 --stop-address=0x44d906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0546219c00`), re-decoding lands at `0x64bc831`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 174, column 42. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
