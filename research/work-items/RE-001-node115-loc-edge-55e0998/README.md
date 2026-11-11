# RE-001: map node #115 l1/bole/user_state.rs:239 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/bole/user_state.rs` as an embedded path. At ELF VA `0x55e0998` (file offset `0x55df998`), `488d150999ec00` decodes as `lea rdx, [rip + 0xec9909]`. Adding the signed displacement `15505673` to the next instruction VA `0x55e099f` yields `0x64aa2a8`. The decode from the start of FDE range `[0x55defd0, 0x55e16ca)` reaches that instruction boundary. The FDE itself is at `0x135e300`.

At `0x64aa2a8` (file offset `0x64a82a8`), an `R_X86_64_RELATIVE` relocation points to `0x44f5fb` in `.rodata`. The next 16 bytes, `1900000000000000ef0000002c000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 239 and 44. The string's normalized suffix matches `l1/bole/user_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x55e0961` is `0x55e0a57` and the fallthrough is `0x55e0967`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, qword ptr [r15 + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55e095d` | `493b5718` | `cmp rdx, qword ptr [r15 + 0x18]` |
| `0x55e0961` | `0f83f0000000` | `jae 0x55e0a57` |
| `0x55e0967` | `49035710` | `add rdx, qword ptr [r15 + 0x10]` |
| `0x55e096b` | `4c39e2` | `cmp rdx, r12` |
| `0x55e096e` | `b800000000` | `mov eax, 0` |
| `0x55e0973` | `490f43c4` | `cmovae rax, r12` |
| `0x55e0977` | `4829c2` | `sub rdx, rax` |
| `0x55e097a` | `498b4708` | `mov rax, qword ptr [r15 + 8]` |
| `0x55e097e` | `4869cab8000000` | `imul rcx, rdx, 0xb8` |
| `0x55e0985` | `4c8d2c08` | `lea r13, [rax + rcx]` |
| `0x55e0989` | `4983c508` | `add r13, 8` |
| `0x55e098d` | `488dbc24a0000000` | `lea rdi, [rsp + 0xa0]` |
| `0x55e0995` | `4c89ee` | `mov rsi, r13` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 15756939 added to `0x55e09a5` gives the relocation slot `0x64e7830`. Its symbol-zero RELATIVE addend is `0x36a0040`. The target's FDE at `0xe00cc4` describes `[0x36a0040, 0x36a01f9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55e099f` | `ff158b6ef000` | `call qword ptr [rip + 0xf06e8b]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa2a8 '
readelf -rW "$target" | grep -i '0*64e7830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55defd0 --stop-address=0x55e09a5 "$target"
od -An -tx1 -j 105546416 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5fb --stop-address=0x44f614 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d150a99ec00`), re-decoding lands at `0x64aa2a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 239, column 44. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
