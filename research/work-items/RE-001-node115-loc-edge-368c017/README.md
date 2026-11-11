# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x368c017` (file offset `0x368b017`), `488d351acbdd02` decodes as `lea rsi, [rip + 0x2ddcb1a]`. Adding the signed displacement `48089882` to the next instruction VA `0x368c01e` yields `0x6468b38`. The decode from the start of FDE range `[0x368b9d0, 0x368c5ab)` reaches that instruction boundary. The FDE itself is at `0x11eec70`.

At `0x6468b38` (file offset `0x6466b38`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x368bf6d` is `0x368bf98` and the fallthrough is `0x368bf6f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rcx, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368bf6a` | `4885c9` | `test rcx, rcx` |
| `0x368bf6d` | `7429` | `je 0x368bf98` |
| `0x368bf98` | `31d2` | `xor edx, edx` |
| `0x368bf9a` | `31c0` | `xor eax, eax` |
| `0x368bf9c` | `31f6` | `xor esi, esi` |
| `0x368bf9e` | `488b4c2410` | `mov rcx, qword ptr [rsp + 0x10]` |
| `0x368bfa3` | `488b4920` | `mov rcx, qword ptr [rcx + 0x20]` |
| `0x368bfa7` | `488d3c52` | `lea rdi, [rdx + rdx*2]` |
| `0x368bfab` | `48c1e704` | `shl rdi, 4` |
| `0x368bfaf` | `4801cf` | `add rdi, rcx` |
| `0x368bfb2` | `488d0440` | `lea rax, [rax + rax*2]` |
| `0x368bfb6` | `48c1e004` | `shl rax, 4` |
| `0x368bfba` | `4801c8` | `add rax, rcx` |
| `0x368bfbd` | `488d1476` | `lea rdx, [rsi + rsi*2]` |
| `0x368bfc1` | `48c1e204` | `shl rdx, 4` |
| `0x368bfc5` | `4801ca` | `add rdx, rcx` |
| `0x368bfc8` | `41b802000000` | `mov r8d, 2` |
| `0x368bfce` | `4c89442440` | `mov qword ptr [rsp + 0x40], r8` |
| `0x368bfd3` | `48897c2448` | `mov qword ptr [rsp + 0x48], rdi` |
| `0x368bfd8` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x368bfdd` | `48894c2458` | `mov qword ptr [rsp + 0x58], rcx` |
| `0x368bfe2` | `4889542460` | `mov qword ptr [rsp + 0x60], rdx` |
| `0x368bfe7` | `48c744246800000000` | `mov qword ptr [rsp + 0x68], 0` |
| `0x368bff0` | `4889442470` | `mov qword ptr [rsp + 0x70], rax` |
| `0x368bff5` | `48894c2478` | `mov qword ptr [rsp + 0x78], rcx` |
| `0x368bffa` | `4889b42480000000` | `mov qword ptr [rsp + 0x80], rsi` |
| `0x368c002` | `488d842460010000` | `lea rax, [rsp + 0x160]` |
| `0x368c00a` | `4889842488000000` | `mov qword ptr [rsp + 0x88], rax` |
| `0x368c012` | `488d7c2440` | `lea rdi, [rsp + 0x40]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed call displacement 13396013 added to `0x368c023` gives `0x4352850`. The target's FDE at `0xe9e37c` describes `[0x4352850, 0x4352bc9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368c01e` | `e82d68cc00` | `call 0x4352850` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6468b38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x368b9d0 --stop-address=0x368c023 "$target"
od -An -tx1 -j 105278272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d351bcbdd02`), re-decoding lands at `0x6468b39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
