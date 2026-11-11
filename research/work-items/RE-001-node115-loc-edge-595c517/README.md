# RE-001: map node #115 node/consensus/validator_set.rs:164 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/consensus/validator_set.rs` as an embedded path. At ELF VA `0x595c517` (file offset `0x595b517`), `488d0d7aa3b500` decodes as `lea rcx, [rip + 0xb5a37a]`. Adding the signed displacement `11903866` to the next instruction VA `0x595c51e` yields `0x64b6898`. The decode from the start of FDE range `[0x595c3a0, 0x595c5f3)` reaches that instruction boundary. The FDE itself is at `0xfba9e8`.

At `0x64b6898` (file offset `0x64b4898`), an `R_X86_64_RELATIVE` relocation points to `0x44bf91` in `.rodata`. The next 16 bytes, `2300000000000000a40000000d000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 164 and 13. The string's normalized suffix matches `node/consensus/validator_set.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x595c42b` is `0x595c53c` and the fallthrough is `0x595c431`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp r14, rdx`. The recorded edge is selected when the `jb` predicate (`CF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x595c428` | `4939d6` | `cmp r14, rdx` |
| `0x595c42b` | `0f820b010000` | `jb 0x595c53c` |
| `0x595c431` | `488d4660` | `lea rax, [rsi + 0x60]` |
| `0x595c435` | `f048ff4668` | `lock inc qword ptr [rsi + 0x68]` |
| `0x595c43a` | `4889542410` | `mov qword ptr [rsp + 0x10], rdx` |
| `0x595c43f` | `48c744247000000000` | `mov qword ptr [rsp + 0x70], 0` |
| `0x595c448` | `c784248000000000000000` | `mov dword ptr [rsp + 0x80], 0` |
| `0x595c453` | `66c78424840000000000` | `mov word ptr [rsp + 0x84], 0` |
| `0x595c45d` | `c684248000000001` | `mov byte ptr [rsp + 0x80], 1` |
| `0x595c465` | `488d8c2488000000` | `lea rcx, [rsp + 0x88]` |
| `0x595c46d` | `48898c24a8000000` | `mov qword ptr [rsp + 0xa8], rcx` |
| `0x595c475` | `488d0da49ecbff` | `lea rcx, [rip - 0x34615c]` |
| `0x595c47c` | `48898c24b0000000` | `mov qword ptr [rsp + 0xb0], rcx` |
| `0x595c484` | `488d0db10daefa` | `lea rcx, [rip - 0x551f24f]` |
| `0x595c48b` | `48898c2498000000` | `mov qword ptr [rsp + 0x98], rcx` |
| `0x595c493` | `488d8c24a8000000` | `lea rcx, [rsp + 0xa8]` |
| `0x595c49b` | `48898c24a0000000` | `mov qword ptr [rsp + 0xa0], rcx` |
| `0x595c4a3` | `488d4c2408` | `lea rcx, [rsp + 8]` |
| `0x595c4a8` | `48894c2418` | `mov qword ptr [rsp + 0x18], rcx` |
| `0x595c4ad` | `488d4c2410` | `lea rcx, [rsp + 0x10]` |
| `0x595c4b2` | `48894c2420` | `mov qword ptr [rsp + 0x20], rcx` |
| `0x595c4b7` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x595c4bc` | `488d842498000000` | `lea rax, [rsp + 0x98]` |
| `0x595c4c4` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x595c4c9` | `488d0550ddecff` | `lea rax, [rip - 0x1322b0]` |
| `0x595c4d0` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x595c4d5` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x595c4da` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x595c4df` | `488d053adbecff` | `lea rax, [rip - 0x1324c6]` |
| `0x595c4e6` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x595c4eb` | `488d442420` | `lea rax, [rsp + 0x20]` |
| `0x595c4f0` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x595c4f5` | `488d0524dcecff` | `lea rax, [rip - 0x1323dc]` |
| `0x595c4fc` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x595c501` | `488d4c2428` | `lea rcx, [rsp + 0x28]` |
| `0x595c506` | `48894c2460` | `mov qword ptr [rsp + 0x60], rcx` |
| `0x595c50b` | `4889442468` | `mov qword ptr [rsp + 0x68], rax` |
| `0x595c510` | `488d051347adfa` | `lea rax, [rip - 0x552b8ed]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 12076516 added to `0x595c534` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x595c51e` | `488d7c2470` | `lea rdi, [rsp + 0x70]` |
| `0x595c523` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x595c528` | `4989f6` | `mov r14, rsi` |
| `0x595c52b` | `4889c6` | `mov rsi, rax` |
| `0x595c52e` | `ff15e445b800` | `call qword ptr [rip + 0xb845e4]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b6898 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x595c3a0 --stop-address=0x595c534 "$target"
od -An -tx1 -j 105597088 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44bf91 --stop-address=0x44bfb4 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d7ba3b500`), re-decoding lands at `0x64b6899`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 164, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
