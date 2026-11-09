# RE-001: map node #115 base/file_mod_time_tracker.rs:119 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x57d2415` (file offset `0x57d1415`), `488d0de4e7cd00` decodes as `lea rcx, [rip + 0xcde7e4]`. Adding the signed displacement `13494244` to the next instruction VA `0x57d241c` yields `0x64b0c00`. The decode from the start of FDE range `[0x57d2200, 0x57d25d4)` reaches that instruction boundary. The FDE itself is at `0x1376f58`.

At `0x64b0c00` (file offset `0x64aec00`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000007700000011000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 119 and 17. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x57d239f` is `0x57d249e` and the fallthrough is `0x57d23a5`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp dword ptr [rsp + 0x88], 2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57d2397` | `83bc248800000002` | `cmp dword ptr [rsp + 0x88], 2` |
| `0x57d239f` | `0f85f9000000` | `jne 0x57d249e` |
| `0x57d23a5` | `488b842490000000` | `mov rax, qword ptr [rsp + 0x90]` |
| `0x57d23ad` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x57d23b2` | `48c744243000000000` | `mov qword ptr [rsp + 0x30], 0` |
| `0x57d23bb` | `c744244000000000` | `mov dword ptr [rsp + 0x40], 0` |
| `0x57d23c3` | `66c74424440000` | `mov word ptr [rsp + 0x44], 0` |
| `0x57d23ca` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x57d23cf` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x57d23d4` | `488b054dd8d000` | `mov rax, qword ptr [rip + 0xd0d84d]` |
| `0x57d23db` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x57d23e0` | `488d051ab8c6fa` | `lea rax, [rip - 0x53947e6]` |
| `0x57d23e7` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x57d23ec` | `488d442420` | `lea rax, [rsp + 0x20]` |
| `0x57d23f1` | `4889842480000000` | `mov qword ptr [rsp + 0x80], rax` |
| `0x57d23f9` | `488d442478` | `lea rax, [rsp + 0x78]` |
| `0x57d23fe` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x57d2402` | `488d05177e0500` | `lea rax, [rip + 0x57e17]` |
| `0x57d2409` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x57d240e` | `488d354294c6fa` | `lea rsi, [rip - 0x5396bbe]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 13690606 added to `0x57d242a` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57d241c` | `488d7c2430` | `lea rdi, [rsp + 0x30]` |
| `0x57d2421` | `4889e2` | `mov rdx, rsp` |
| `0x57d2424` | `ff15eee6d000` | `call qword ptr [rip + 0xd0e6ee]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c00 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x57d2200 --stop-address=0x57d242a "$target"
od -An -tx1 -j 105573384 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0de5e7cd00`), re-decoding lands at `0x64b0c01`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
