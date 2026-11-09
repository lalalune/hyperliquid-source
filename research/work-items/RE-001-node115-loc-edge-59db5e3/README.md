# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x59db5e3` (file offset `0x59da5e3`), `488d0d2e56ad00` decodes as `lea rcx, [rip + 0xad562e]`. Adding the signed displacement `11359790` to the next instruction VA `0x59db5ea` yields `0x64b0c18`. The decode from the start of FDE range `[0x59db3a0, 0x59db6f4)` reaches that instruction boundary. The FDE itself is at `0xfbd520`.

At `0x64b0c18` (file offset `0x64aec18`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x59db578` is `0x59db5f8` and the fallthrough is `0x59db57a`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [r14 + 0x60], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x59db573` | `49837e6000` | `cmp qword ptr [r14 + 0x60], 0` |
| `0x59db578` | `747e` | `je 0x59db5f8` |
| `0x59db57a` | `498d4660` | `lea rax, [r14 + 0x60]` |
| `0x59db57e` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x59db583` | `48c7042400000000` | `mov qword ptr [rsp], 0` |
| `0x59db58b` | `c744241000000000` | `mov dword ptr [rsp + 0x10], 0` |
| `0x59db593` | `66c74424140000` | `mov word ptr [rsp + 0x14], 0` |
| `0x59db59a` | `488d442450` | `lea rax, [rsp + 0x50]` |
| `0x59db59f` | `4889442468` | `mov qword ptr [rsp + 0x68], rax` |
| `0x59db5a4` | `488d0505e045ff` | `lea rax, [rip - 0xba1ffb]` |
| `0x59db5ab` | `4889442470` | `mov qword ptr [rsp + 0x70], rax` |
| `0x59db5b0` | `488d05b086a6fa` | `lea rax, [rip - 0x5597950]` |
| `0x59db5b7` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x59db5bc` | `488d442468` | `lea rax, [rsp + 0x68]` |
| `0x59db5c1` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x59db5c6` | `488d442458` | `lea rax, [rsp + 0x58]` |
| `0x59db5cb` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x59db5d0` | `488d0549ece4ff` | `lea rax, [rip - 0x1b13b7]` |
| `0x59db5d7` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x59db5dc` | `488d357402a6fa` | `lea rsi, [rip - 0x559fd8c]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 11556128 added to `0x59db5f8` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x59db5ea` | `4889e7` | `mov rdi, rsp` |
| `0x59db5ed` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x59db5f2` | `ff152055b000` | `call qword ptr [rip + 0xb05520]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c18 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x59db3a0 --stop-address=0x59db5f8 "$target"
od -An -tx1 -j 105573408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d2f56ad00`), re-decoding lands at `0x64b0c19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
