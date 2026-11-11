# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x565c3cb` (file offset `0x565b3cb`), `488d0d4648e500` decodes as `lea rcx, [rip + 0xe54846]`. Adding the signed displacement `15026246` to the next instruction VA `0x565c3d2` yields `0x64b0c18`. The decode from the start of FDE range `[0x565c340, 0x565c3ee)` reaches that instruction boundary. The FDE itself is at `0xf8bb18`.

At `0x64b0c18` (file offset `0x64aec18`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x565c359` is `0x565c3ed` and the fallthrough is `0x565c35f`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rcx + 0x80], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x565c351` | `4883b98000000000` | `cmp qword ptr [rcx + 0x80], 0` |
| `0x565c359` | `0f848e000000` | `je 0x565c3ed` |
| `0x565c35f` | `53` | `push rbx` |
| `0x565c360` | `4883ec50` | `sub rsp, 0x50` |
| `0x565c364` | `4883e980` | `sub rcx, -0x80` |
| `0x565c368` | `48890c24` | `mov qword ptr [rsp], rcx` |
| `0x565c36c` | `48c744243800000000` | `mov qword ptr [rsp + 0x38], 0` |
| `0x565c375` | `c744244800000000` | `mov dword ptr [rsp + 0x48], 0` |
| `0x565c37d` | `66c744244c0000` | `mov word ptr [rsp + 0x4c], 0` |
| `0x565c384` | `4889e1` | `mov rcx, rsp` |
| `0x565c387` | `48894c2418` | `mov qword ptr [rsp + 0x18], rcx` |
| `0x565c38c` | `488d0d1dd27dff` | `lea rcx, [rip - 0x822de3]` |
| `0x565c393` | `48894c2420` | `mov qword ptr [rsp + 0x20], rcx` |
| `0x565c398` | `488d0dc878defa` | `lea rcx, [rip - 0x5218738]` |
| `0x565c39f` | `48894c2408` | `mov qword ptr [rsp + 8], rcx` |
| `0x565c3a4` | `488d4c2418` | `lea rcx, [rsp + 0x18]` |
| `0x565c3a9` | `48894c2410` | `mov qword ptr [rsp + 0x10], rcx` |
| `0x565c3ae` | `488d4c2408` | `lea rcx, [rsp + 8]` |
| `0x565c3b3` | `48894c2428` | `mov qword ptr [rsp + 0x28], rcx` |
| `0x565c3b8` | `488d0d61de1c00` | `lea rcx, [rip + 0x1cde61]` |
| `0x565c3bf` | `48894c2430` | `mov qword ptr [rsp + 0x30], rcx` |
| `0x565c3c4` | `488d358cf4ddfa` | `lea rsi, [rip - 0x5220b74]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 15222579 added to `0x565c3e5` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x565c3d2` | `488d7c2438` | `lea rdi, [rsp + 0x38]` |
| `0x565c3d7` | `488d542428` | `lea rdx, [rsp + 0x28]` |
| `0x565c3dc` | `4889c3` | `mov rbx, rax` |
| `0x565c3df` | `ff153347e800` | `call qword ptr [rip + 0xe84733]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c18 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x565c340 --stop-address=0x565c3e5 "$target"
od -An -tx1 -j 105573408 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d4748e500`), re-decoding lands at `0x64b0c19`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
