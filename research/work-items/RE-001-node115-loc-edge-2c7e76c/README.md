# RE-001: map node #115 base/file_mod_time_tracker.rs:119 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x2c7e76c` (file offset `0x2c7d76c`), `488d0df5f37c03` decodes as `lea rcx, [rip + 0x37cf3f5]`. Adding the signed displacement `58520565` to the next instruction VA `0x2c7e773` yields `0x644db68`. The decode from the start of FDE range `[0x2c7e4d0, 0x2c7e9cc)` reaches that instruction boundary. The FDE itself is at `0x118e320`.

At `0x644db68` (file offset `0x644bb68`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000007700000011000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 119 and 17. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c7e67e` is `0x2c7e6f4` and the fallthrough is `0x2c7e680`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r13, r13`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c7e67b` | `4d85ed` | `test r13, r13` |
| `0x2c7e67e` | `7474` | `je 0x2c7e6f4` |
| `0x2c7e6f4` | `4c89742470` | `mov qword ptr [rsp + 0x70], r14` |
| `0x2c7e6f9` | `48c744244800000000` | `mov qword ptr [rsp + 0x48], 0` |
| `0x2c7e702` | `c744245800000000` | `mov dword ptr [rsp + 0x58], 0` |
| `0x2c7e70a` | `66c744245c0000` | `mov word ptr [rsp + 0x5c], 0` |
| `0x2c7e711` | `488d442470` | `lea rax, [rsp + 0x70]` |
| `0x2c7e716` | `4889842498000000` | `mov qword ptr [rsp + 0x98], rax` |
| `0x2c7e71e` | `488b0503158603` | `mov rax, qword ptr [rip + 0x3861503]` |
| `0x2c7e725` | `48898424a0000000` | `mov qword ptr [rsp + 0xa0], rax` |
| `0x2c7e72d` | `488d05cdf47bfd` | `lea rax, [rip - 0x2840b33]` |
| `0x2c7e734` | `4889842488000000` | `mov qword ptr [rsp + 0x88], rax` |
| `0x2c7e73c` | `488d842498000000` | `lea rax, [rsp + 0x98]` |
| `0x2c7e744` | `4889842490000000` | `mov qword ptr [rsp + 0x90], rax` |
| `0x2c7e74c` | `488d842488000000` | `lea rax, [rsp + 0x88]` |
| `0x2c7e754` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x2c7e759` | `488d05b01e98ff` | `lea rax, [rip - 0x67e150]` |
| `0x2c7e760` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x2c7e765` | `488d35ebd07bfd` | `lea rsi, [rip - 0x2842f15]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 59122581 added to `0x2c7e783` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c7e773` | `488d7c2448` | `lea rdi, [rsp + 0x48]` |
| `0x2c7e778` | `488d542438` | `lea rdx, [rsp + 0x38]` |
| `0x2c7e77d` | `ff1595238603` | `call qword ptr [rip + 0x3862395]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644db68 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c7e4d0 --stop-address=0x2c7e783 "$target"
od -An -tx1 -j 105167728 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0df6f37c03`), re-decoding lands at `0x644db69`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
