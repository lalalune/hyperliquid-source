# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x4fbfbba` (file offset `0x4fbebba`), `488d0d57104f01` decodes as `lea rcx, [rip + 0x14f1057]`. Adding the signed displacement `21958743` to the next instruction VA `0x4fbfbc1` yields `0x64b0c18`. The decode from the start of FDE range `[0x4fbfa10, 0x4fc015b)` reaches that instruction boundary. The FDE itself is at `0x1313f04`.

At `0x64b0c18` (file offset `0x64aec18`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4fbfb43` is `0x4fbfbd1` and the fallthrough is `0x4fbfb49`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rbx + 0x700], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4fbfb3b` | `4883bb0007000000` | `cmp qword ptr [rbx + 0x700], 0` |
| `0x4fbfb43` | `0f8488000000` | `je 0x4fbfbd1` |
| `0x4fbfb49` | `488d8300070000` | `lea rax, [rbx + 0x700]` |
| `0x4fbfb50` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x4fbfb55` | `48c744241000000000` | `mov qword ptr [rsp + 0x10], 0` |
| `0x4fbfb5e` | `c744242000000000` | `mov dword ptr [rsp + 0x20], 0` |
| `0x4fbfb66` | `66c74424240000` | `mov word ptr [rsp + 0x24], 0` |
| `0x4fbfb6d` | `488d442460` | `lea rax, [rsp + 0x60]` |
| `0x4fbfb72` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x4fbfb77` | `488d05329ae7ff` | `lea rax, [rip - 0x1865ce]` |
| `0x4fbfb7e` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x4fbfb83` | `488d05dd4048fb` | `lea rax, [rip - 0x4b7bf23]` |
| `0x4fbfb8a` | `4889842480000000` | `mov qword ptr [rsp + 0x80], rax` |
| `0x4fbfb92` | `4c89b42488000000` | `mov qword ptr [rsp + 0x88], r14` |
| `0x4fbfb9a` | `488d842480000000` | `lea rax, [rsp + 0x80]` |
| `0x4fbfba2` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x4fbfba7` | `488d0572a68600` | `lea rax, [rip + 0x86a672]` |
| `0x4fbfbae` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x4fbfbb3` | `488d359dbc47fb` | `lea rsi, [rip - 0x4b84363]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 22155079 added to `0x4fbfbd1` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4fbfbc1` | `488d7c2410` | `lea rdi, [rsp + 0x10]` |
| `0x4fbfbc6` | `488d542430` | `lea rdx, [rsp + 0x30]` |
| `0x4fbfbcb` | `ff15470f5201` | `call qword ptr [rip + 0x1520f47]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c18 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4fbfa10 --stop-address=0x4fbfbd1 "$target"
od -An -tx1 -j 105573408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d58104f01`), re-decoding lands at `0x64b0c19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
