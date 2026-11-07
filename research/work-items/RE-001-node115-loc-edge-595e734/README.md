# RE-001: map node #115 node/consensus/validator_set.rs:164 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/consensus/validator_set.rs` as an embedded path. At ELF VA `0x595e734` (file offset `0x595d734`), `488d0d5d81b500` decodes as `lea rcx, [rip + 0xb5815d]`. Adding the signed displacement `11895133` to the next instruction VA `0x595e73b` yields `0x64b6898`. The decode from the start of FDE range `[0x595e5c0, 0x595e80a)` reaches that instruction boundary. The FDE itself is at `0xfbaa60`.

At `0x64b6898` (file offset `0x64b4898`), an `R_X86_64_RELATIVE` relocation points to `0x44bf91` in `.rodata`. The next 16 bytes, `2300000000000000a40000000d000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 164 and 13. The string's normalized suffix matches `node/consensus/validator_set.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x595e648` is `0x595e772` and the fallthrough is `0x595e64e`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp r14, rdi`. The recorded edge is selected when the `jb` predicate (`CF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x595e645` | `4939fe` | `cmp r14, rdi` |
| `0x595e648` | `0f8224010000` | `jb 0x595e772` |
| `0x595e64e` | `488d4660` | `lea rax, [rsi + 0x60]` |
| `0x595e652` | `f048ff4668` | `lock inc qword ptr [rsi + 0x68]` |
| `0x595e657` | `48897c2410` | `mov qword ptr [rsp + 0x10], rdi` |
| `0x595e65c` | `48c744247000000000` | `mov qword ptr [rsp + 0x70], 0` |
| `0x595e665` | `c784248000000000000000` | `mov dword ptr [rsp + 0x80], 0` |
| `0x595e670` | `66c78424840000000000` | `mov word ptr [rsp + 0x84], 0` |
| `0x595e67a` | `c684248000000001` | `mov byte ptr [rsp + 0x80], 1` |
| `0x595e682` | `488d8c2488000000` | `lea rcx, [rsp + 0x88]` |
| `0x595e68a` | `48898c24a8000000` | `mov qword ptr [rsp + 0xa8], rcx` |
| `0x595e692` | `488d0d877ccbff` | `lea rcx, [rip - 0x348379]` |
| `0x595e699` | `48898c24b0000000` | `mov qword ptr [rsp + 0xb0], rcx` |
| `0x595e6a1` | `488d0d94ebadfa` | `lea rcx, [rip - 0x552146c]` |
| `0x595e6a8` | `48898c2498000000` | `mov qword ptr [rsp + 0x98], rcx` |
| `0x595e6b0` | `488d8c24a8000000` | `lea rcx, [rsp + 0xa8]` |
| `0x595e6b8` | `48898c24a0000000` | `mov qword ptr [rsp + 0xa0], rcx` |
| `0x595e6c0` | `488d4c2408` | `lea rcx, [rsp + 8]` |
| `0x595e6c5` | `48894c2418` | `mov qword ptr [rsp + 0x18], rcx` |
| `0x595e6ca` | `488d4c2410` | `lea rcx, [rsp + 0x10]` |
| `0x595e6cf` | `48894c2420` | `mov qword ptr [rsp + 0x20], rcx` |
| `0x595e6d4` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x595e6d9` | `488d842498000000` | `lea rax, [rsp + 0x98]` |
| `0x595e6e1` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x595e6e6` | `488d0533bbecff` | `lea rax, [rip - 0x1344cd]` |
| `0x595e6ed` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x595e6f2` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x595e6f7` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x595e6fc` | `488d051db9ecff` | `lea rax, [rip - 0x1346e3]` |
| `0x595e703` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x595e708` | `488d442420` | `lea rax, [rsp + 0x20]` |
| `0x595e70d` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x595e712` | `488d0507baecff` | `lea rax, [rip - 0x1345f9]` |
| `0x595e719` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x595e71e` | `488d4c2428` | `lea rcx, [rsp + 0x28]` |
| `0x595e723` | `48894c2460` | `mov qword ptr [rsp + 0x60], rcx` |
| `0x595e728` | `4889442468` | `mov qword ptr [rsp + 0x68], rax` |
| `0x595e72d` | `488d05f624adfa` | `lea rax, [rip - 0x552db0a]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 12067783 added to `0x595e751` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x595e73b` | `488d7c2470` | `lea rdi, [rsp + 0x70]` |
| `0x595e740` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x595e745` | `4989f6` | `mov r14, rsi` |
| `0x595e748` | `4889c6` | `mov rsi, rax` |
| `0x595e74b` | `ff15c723b800` | `call qword ptr [rip + 0xb823c7]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b6898 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x595e5c0 --stop-address=0x595e751 "$target"
od -An -tx1 -j 105597088 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44bf91 --stop-address=0x44bfb4 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d5e81b500`), re-decoding lands at `0x64b6899`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 164, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
