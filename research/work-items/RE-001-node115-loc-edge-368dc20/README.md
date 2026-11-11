# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x368dc20` (file offset `0x368cc20`), `488d3511afdd02` decodes as `lea rsi, [rip + 0x2ddaf11]`. Adding the signed displacement `48082705` to the next instruction VA `0x368dc27` yields `0x6468b38`. The decode from the start of FDE range `[0x368d380, 0x368e2dd)` reaches that instruction boundary. The FDE itself is at `0x11eed18`.

At `0x6468b38` (file offset `0x6466b38`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x368db78` is `0x368dba3` and the fallthrough is `0x368db7a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rcx, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368db75` | `4885c9` | `test rcx, rcx` |
| `0x368db78` | `7429` | `je 0x368dba3` |
| `0x368dba3` | `31d2` | `xor edx, edx` |
| `0x368dba5` | `31c0` | `xor eax, eax` |
| `0x368dba7` | `31f6` | `xor esi, esi` |
| `0x368dba9` | `498b4d20` | `mov rcx, qword ptr [r13 + 0x20]` |
| `0x368dbad` | `4889d7` | `mov rdi, rdx` |
| `0x368dbb0` | `48c1e707` | `shl rdi, 7` |
| `0x368dbb4` | `488d3cd7` | `lea rdi, [rdi + rdx*8]` |
| `0x368dbb8` | `4801cf` | `add rdi, rcx` |
| `0x368dbbb` | `4889c2` | `mov rdx, rax` |
| `0x368dbbe` | `48c1e207` | `shl rdx, 7` |
| `0x368dbc2` | `488d04c2` | `lea rax, [rdx + rax*8]` |
| `0x368dbc6` | `4801c8` | `add rax, rcx` |
| `0x368dbc9` | `4889f2` | `mov rdx, rsi` |
| `0x368dbcc` | `48c1e207` | `shl rdx, 7` |
| `0x368dbd0` | `488d14f2` | `lea rdx, [rdx + rsi*8]` |
| `0x368dbd4` | `4801ca` | `add rdx, rcx` |
| `0x368dbd7` | `41b802000000` | `mov r8d, 2` |
| `0x368dbdd` | `4c89442420` | `mov qword ptr [rsp + 0x20], r8` |
| `0x368dbe2` | `48897c2428` | `mov qword ptr [rsp + 0x28], rdi` |
| `0x368dbe7` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x368dbec` | `48894c2438` | `mov qword ptr [rsp + 0x38], rcx` |
| `0x368dbf1` | `4889542440` | `mov qword ptr [rsp + 0x40], rdx` |
| `0x368dbf6` | `48c744244800000000` | `mov qword ptr [rsp + 0x48], 0` |
| `0x368dbff` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x368dc04` | `48894c2458` | `mov qword ptr [rsp + 0x58], rcx` |
| `0x368dc09` | `4889742460` | `mov qword ptr [rsp + 0x60], rsi` |
| `0x368dc0e` | `488d84244f020000` | `lea rax, [rsp + 0x24f]` |
| `0x368dc16` | `4889442468` | `mov qword ptr [rsp + 0x68], rax` |
| `0x368dc1b` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed call displacement 13389732 added to `0x368dc2c` gives `0x4352bd0`. The target's FDE at `0xe9e3cc` describes `[0x4352bd0, 0x435310e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368dc27` | `e8a44fcc00` | `call 0x4352bd0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6468b38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x368d380 --stop-address=0x368dc2c "$target"
od -An -tx1 -j 105278272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3512afdd02`), re-decoding lands at `0x6468b39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
