# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x4fbb780` (file offset `0x4fba780`), `488d0d91544f01` decodes as `lea rcx, [rip + 0x14f5491]`. Adding the signed displacement `21976209` to the next instruction VA `0x4fbb787` yields `0x64b0c18`. The decode from the start of FDE range `[0x4fbb630, 0x4fbba00)` reaches that instruction boundary. The FDE itself is at `0x1313a1c`.

At `0x64b0c18` (file offset `0x64aec18`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4fbb710` is `0x4fbb797` and the fallthrough is `0x4fbb716`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rbx + 0x60], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4fbb70b` | `48837b6000` | `cmp qword ptr [rbx + 0x60], 0` |
| `0x4fbb710` | `0f8481000000` | `je 0x4fbb797` |
| `0x4fbb716` | `488d4360` | `lea rax, [rbx + 0x60]` |
| `0x4fbb71a` | `48898424b0000000` | `mov qword ptr [rsp + 0xb0], rax` |
| `0x4fbb722` | `48c744242000000000` | `mov qword ptr [rsp + 0x20], 0` |
| `0x4fbb72b` | `c744243000000000` | `mov dword ptr [rsp + 0x30], 0` |
| `0x4fbb733` | `66c74424340000` | `mov word ptr [rsp + 0x34], 0` |
| `0x4fbb73a` | `488d8424b0000000` | `lea rax, [rsp + 0xb0]` |
| `0x4fbb742` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x4fbb746` | `488d0563dee7ff` | `lea rax, [rip - 0x18219d]` |
| `0x4fbb74d` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x4fbb752` | `488d050e8548fb` | `lea rax, [rip - 0x4b77af2]` |
| `0x4fbb759` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x4fbb75e` | `4c89642468` | `mov qword ptr [rsp + 0x68], r12` |
| `0x4fbb763` | `488d442460` | `lea rax, [rsp + 0x60]` |
| `0x4fbb768` | `4889442470` | `mov qword ptr [rsp + 0x70], rax` |
| `0x4fbb76d` | `488d05acea8600` | `lea rax, [rip + 0x86eaac]` |
| `0x4fbb774` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x4fbb779` | `488d35d70048fb` | `lea rsi, [rip - 0x4b7ff29]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 22172545 added to `0x4fbb797` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4fbb787` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x4fbb78c` | `488d542470` | `lea rdx, [rsp + 0x70]` |
| `0x4fbb791` | `ff1581535201` | `call qword ptr [rip + 0x1525381]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c18 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4fbb630 --stop-address=0x4fbb797 "$target"
od -An -tx1 -j 105573408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d92544f01`), re-decoding lands at `0x64b0c19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
