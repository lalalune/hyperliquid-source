# RE-001: map node #115 base/file_mod_time_tracker.rs:119 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x477e09e` (file offset `0x477d09e`), `488d0dd38dd101` decodes as `lea rcx, [rip + 0x1d18dd3]`. Adding the signed displacement `30510547` to the next instruction VA `0x477e0a5` yields `0x6496e78`. The decode from the start of FDE range `[0x477dea0, 0x477e298)` reaches that instruction boundary. The FDE itself is at `0x12c8300`.

At `0x6496e78` (file offset `0x6494e78`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000007700000011000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 119 and 17. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x477e009` is `0x477e038` and the fallthrough is `0x477e00b`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r13, r13`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x477e006` | `4d85ed` | `test r13, r13` |
| `0x477e009` | `742d` | `je 0x477e038` |
| `0x477e038` | `48896c2430` | `mov qword ptr [rsp + 0x30], rbp` |
| `0x477e03d` | `48c744240800000000` | `mov qword ptr [rsp + 8], 0` |
| `0x477e046` | `c744241800000000` | `mov dword ptr [rsp + 0x18], 0` |
| `0x477e04e` | `66c744241c0000` | `mov word ptr [rsp + 0x1c], 0` |
| `0x477e055` | `488d442430` | `lea rax, [rsp + 0x30]` |
| `0x477e05a` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x477e05f` | `488b05c21bd601` | `mov rax, qword ptr [rip + 0x1d61bc2]` |
| `0x477e066` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x477e06b` | `488d058ffbcbfb` | `lea rax, [rip - 0x4340471]` |
| `0x477e072` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x477e077` | `488d442440` | `lea rax, [rsp + 0x40]` |
| `0x477e07c` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x477e081` | `488d442458` | `lea rax, [rsp + 0x58]` |
| `0x477e086` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x477e08b` | `488d05debefeff` | `lea rax, [rip - 0x14122]` |
| `0x477e092` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x477e097` | `488d35b9d7cbfb` | `lea rsi, [rip - 0x4342847]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 30812771 added to `0x477e0b5` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x477e0a5` | `488d7c2408` | `lea rdi, [rsp + 8]` |
| `0x477e0aa` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x477e0af` | `ff15632ad601` | `call qword ptr [rip + 0x1d62a63]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6496e78 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x477dea0 --stop-address=0x477e0b5 "$target"
od -An -tx1 -j 105467520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dd48dd101`), re-decoding lands at `0x6496e79`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
