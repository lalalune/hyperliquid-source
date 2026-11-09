# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x4fbed58` (file offset `0x4fbdd58`), `488d0db91e4f01` decodes as `lea rcx, [rip + 0x14f1eb9]`. Adding the signed displacement `21962425` to the next instruction VA `0x4fbed5f` yields `0x64b0c18`. The decode from the start of FDE range `[0x4fbebe0, 0x4fbf26b)` reaches that instruction boundary. The FDE itself is at `0x1313e5c`.

At `0x64b0c18` (file offset `0x64aec18`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4fbecef` is `0x4fbed6d` and the fallthrough is `0x4fbecf1`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rbx + 0x718], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4fbece7` | `4883bb1807000000` | `cmp qword ptr [rbx + 0x718], 0` |
| `0x4fbecef` | `747c` | `je 0x4fbed6d` |
| `0x4fbecf1` | `488d8318070000` | `lea rax, [rbx + 0x718]` |
| `0x4fbecf8` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x4fbecfd` | `48c7042400000000` | `mov qword ptr [rsp], 0` |
| `0x4fbed05` | `c744241000000000` | `mov dword ptr [rsp + 0x10], 0` |
| `0x4fbed0d` | `66c74424140000` | `mov word ptr [rsp + 0x14], 0` |
| `0x4fbed14` | `488d442450` | `lea rax, [rsp + 0x50]` |
| `0x4fbed19` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x4fbed1e` | `488d058ba8e7ff` | `lea rax, [rip - 0x185775]` |
| `0x4fbed25` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x4fbed2a` | `488d05364f48fb` | `lea rax, [rip - 0x4b7b0ca]` |
| `0x4fbed31` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x4fbed36` | `4c89642468` | `mov qword ptr [rsp + 0x68], r12` |
| `0x4fbed3b` | `488d442460` | `lea rax, [rsp + 0x60]` |
| `0x4fbed40` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x4fbed45` | `488d05d4b48600` | `lea rax, [rip + 0x86b4d4]` |
| `0x4fbed4c` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x4fbed51` | `488d35ffca47fb` | `lea rsi, [rip - 0x4b83501]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 22158763 added to `0x4fbed6d` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4fbed5f` | `4889e7` | `mov rdi, rsp` |
| `0x4fbed62` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x4fbed67` | `ff15ab1d5201` | `call qword ptr [rip + 0x1521dab]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c18 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4fbebe0 --stop-address=0x4fbed6d "$target"
od -An -tx1 -j 105573408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dba1e4f01`), re-decoding lands at `0x64b0c19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
