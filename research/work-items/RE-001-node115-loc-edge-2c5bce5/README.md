# RE-001: map node #115 l1/exchange/impl_outcome.rs:355 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_outcome.rs` as an embedded path. At ELF VA `0x2c5bce5` (file offset `0x2c5ace5`), `488d35ac1a7f03` decodes as `lea rsi, [rip + 0x37f1aac]`. Adding the signed displacement `58661548` to the next instruction VA `0x2c5bcec` yields `0x644d798`. The decode from the start of FDE range `[0x2c5bac0, 0x2c5be8e)` reaches that instruction boundary. The FDE itself is at `0x118d1e4`.

At `0x644d798` (file offset `0x644b798`), an `R_X86_64_RELATIVE` relocation points to `0x445ed1` in `.rodata`. The next 16 bytes, `1f000000000000006301000032000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 355 and 50. The string's normalized suffix matches `l1/exchange/impl_outcome.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c5bbb7` is `0x2c5bcc6` and the fallthrough is `0x2c5bbbd`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp al, 0x25`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c5bbb5` | `3c25` | `cmp al, 0x25` |
| `0x2c5bbb7` | `0f8509010000` | `jne 0x2c5bcc6` |
| `0x2c5bcc6` | `8b4510` | `mov eax, dword ptr [rbp + 0x10]` |
| `0x2c5bcc9` | `89442420` | `mov dword ptr [rsp + 0x20], eax` |
| `0x2c5bccd` | `f30f6f4500` | `movdqu xmm0, xmmword ptr [rbp]` |
| `0x2c5bcd2` | `660f7f442410` | `movdqa xmmword ptr [rsp + 0x10], xmm0` |
| `0x2c5bcd8` | `4c8b742430` | `mov r14, qword ptr [rsp + 0x30]` |
| `0x2c5bcdd` | `41c686a802000001` | `mov byte ptr [r14 + 0x2a8], 1` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 59281841 added to `0x2c5bcf7` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c5bcec` | `bf04000000` | `mov edi, 4` |
| `0x2c5bcf1` | `ff15b1918803` | `call qword ptr [rip + 0x38891b1]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d798 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c5bac0 --stop-address=0x2c5bcf7 "$target"
od -An -tx1 -j 105166752 -N 16 "$target"
objdump -s -j .rodata --start-address=0x445ed1 --stop-address=0x445ef0 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35ad1a7f03`), re-decoding lands at `0x644d799`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 355, column 50. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
