# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x2a45af3` (file offset `0x2a44af3`), `488d0d8680a003` decodes as `lea rcx, [rip + 0x3a08086]`. Adding the signed displacement `60850310` to the next instruction VA `0x2a45afa` yields `0x644db80`. The decode from the start of FDE range `[0x2a45950, 0x2a4677c)` reaches that instruction boundary. The FDE itself is at `0x116d1e8`.

At `0x644db80` (file offset `0x644bb80`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2a45a70` is `0x2a45b10` and the fallthrough is `0x2a45a76`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [r15 + 0x718], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a45a68` | `4983bf1807000000` | `cmp qword ptr [r15 + 0x718], 0` |
| `0x2a45a70` | `0f849a000000` | `je 0x2a45b10` |
| `0x2a45a76` | `498d8718070000` | `lea rax, [r15 + 0x718]` |
| `0x2a45a7d` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x2a45a82` | `48c784248000000000000000` | `mov qword ptr [rsp + 0x80], 0` |
| `0x2a45a8e` | `c784249000000000000000` | `mov dword ptr [rsp + 0x90], 0` |
| `0x2a45a99` | `66c78424940000000000` | `mov word ptr [rsp + 0x94], 0` |
| `0x2a45aa3` | `488d442410` | `lea rax, [rsp + 0x10]` |
| `0x2a45aa8` | `48898424a0010000` | `mov qword ptr [rsp + 0x1a0], rax` |
| `0x2a45ab0` | `488d05b9a7f6ff` | `lea rax, [rip - 0x95847]` |
| `0x2a45ab7` | `48898424a8010000` | `mov qword ptr [rsp + 0x1a8], rax` |
| `0x2a45abf` | `488d05a1e19ffd` | `lea rax, [rip - 0x2601e5f]` |
| `0x2a45ac6` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x2a45acb` | `4c89642438` | `mov qword ptr [rsp + 0x38], r12` |
| `0x2a45ad0` | `488d442430` | `lea rax, [rsp + 0x30]` |
| `0x2a45ad5` | `4889842400010000` | `mov qword ptr [rsp + 0x100], rax` |
| `0x2a45add` | `488d052cabbbff` | `lea rax, [rip - 0x4454d4]` |
| `0x2a45ae4` | `4889842408010000` | `mov qword ptr [rsp + 0x108], rax` |
| `0x2a45aec` | `488d35645d9ffd` | `lea rsi, [rip - 0x260a29c]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 61452296 added to `0x2a45b10` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a45afa` | `488dbc2480000000` | `lea rdi, [rsp + 0x80]` |
| `0x2a45b02` | `488d942400010000` | `lea rdx, [rsp + 0x100]` |
| `0x2a45b0a` | `ff1508b0a903` | `call qword ptr [rip + 0x3a9b008]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644db80 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a45950 --stop-address=0x2a45b10 "$target"
od -An -tx1 -j 105167752 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d8780a003`), re-decoding lands at `0x644db81`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
