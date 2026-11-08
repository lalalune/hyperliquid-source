# RE-001: map node #115 base/file_mod_time_tracker.rs:119 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x57d1fe1` (file offset `0x57d0fe1`), `488d0d18eccd00` decodes as `lea rcx, [rip + 0xcdec18]`. Adding the signed displacement `13495320` to the next instruction VA `0x57d1fe8` yields `0x64b0c00`. The decode from the start of FDE range `[0x57d1dc0, 0x57d21ff)` reaches that instruction boundary. The FDE itself is at `0x1376f04`.

At `0x64b0c00` (file offset `0x64aec00`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000007700000011000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 119 and 17. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x57d1f48` is `0x57d1f7c` and the fallthrough is `0x57d1f4a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r13, r13`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57d1f45` | `4d85ed` | `test r13, r13` |
| `0x57d1f48` | `7432` | `je 0x57d1f7c` |
| `0x57d1f7c` | `48896c2428` | `mov qword ptr [rsp + 0x28], rbp` |
| `0x57d1f81` | `48c7042400000000` | `mov qword ptr [rsp], 0` |
| `0x57d1f89` | `c744241000000000` | `mov dword ptr [rsp + 0x10], 0` |
| `0x57d1f91` | `66c74424140000` | `mov word ptr [rsp + 0x14], 0` |
| `0x57d1f98` | `488d442428` | `lea rax, [rsp + 0x28]` |
| `0x57d1f9d` | `4889442438` | `mov qword ptr [rsp + 0x38], rax` |
| `0x57d1fa2` | `488b057fdcd000` | `mov rax, qword ptr [rip + 0xd0dc7f]` |
| `0x57d1fa9` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x57d1fae` | `488d054cbcc6fa` | `lea rax, [rip - 0x53943b4]` |
| `0x57d1fb5` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x57d1fba` | `488d442438` | `lea rax, [rsp + 0x38]` |
| `0x57d1fbf` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x57d1fc4` | `488d442458` | `lea rax, [rsp + 0x58]` |
| `0x57d1fc9` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x57d1fce` | `488d054b820500` | `lea rax, [rip + 0x5824b]` |
| `0x57d1fd5` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x57d1fda` | `488d357698c6fa` | `lea rsi, [rip - 0x539678a]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 13691682 added to `0x57d1ff6` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57d1fe8` | `4889e7` | `mov rdi, rsp` |
| `0x57d1feb` | `488d542418` | `lea rdx, [rsp + 0x18]` |
| `0x57d1ff0` | `ff1522ebd000` | `call qword ptr [rip + 0xd0eb22]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c00 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x57d1dc0 --stop-address=0x57d1ff6 "$target"
od -An -tx1 -j 105573384 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d19eccd00`), re-decoding lands at `0x64b0c01`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
