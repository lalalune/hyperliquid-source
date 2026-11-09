# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:433 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x37c2523` (file offset `0x37c1523`), `488d15b6beca02` decodes as `lea rdx, [rip + 0x2cabeb6]`. Adding the signed displacement `46841526` to the next instruction VA `0x37c252a` yields `0x646e3e0`. The decode from the start of FDE range `[0x37c20f0, 0x37c25f6)` reaches that instruction boundary. The FDE itself is at `0x121391c`.

At `0x646e3e0` (file offset `0x646c3e0`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `2500000000000000b101000012000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 433 and 18. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x37c21ae` is `0x37c24fa` and the fallthrough is `0x37c21b4`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rcx, rsi`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x37c21ab` | `4839f1` | `cmp rcx, rsi` |
| `0x37c21ae` | `0f8346030000` | `jae 0x37c24fa` |
| `0x37c24fa` | `4869ff10270000` | `imul rdi, rdi, 0x2710` |
| `0x37c2501` | `488d043b` | `lea rax, [rbx + rdi]` |
| `0x37c2505` | `48b94b598638d6c56d34` | `movabs rcx, 0x346dc5d63886594b` |
| `0x37c250f` | `48f7e1` | `mul rcx` |
| `0x37c2512` | `48c1ea0b` | `shr rdx, 0xb` |
| `0x37c2516` | `4869c210270000` | `imul rax, rdx, 0x2710` |
| `0x37c251d` | `4829c7` | `sub rdi, rax` |
| `0x37c2520` | `4801df` | `add rdi, rbx` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 47304944 added to `0x37c2530` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

## Callee identification

The resolved callee selects the diagnostic ``index out of bounds: the len is {rsi} but the index is {rdi}``. Its bytes at `0x4400ef` are `20696e646578206f7574206f6620626f756e64733a20746865206c656e20697320c012206275742074686520696e64657820697320c000`. The wrapper's RIP-relative indirect call uses slot `0x64df6b8`, whose RELATIVE addend is the sink at `0x1680e80`. The wrapper trace and sink FDE are recorded alongside the source-location record.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x37c252a` | `ff15f0d0d102` | `call qword ptr [rip + 0x2d1d0f0]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e3e0 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x37c20f0 --stop-address=0x37c2530 "$target"
objdump -d -M intel --start-address=0x1680cbf --stop-address=0x1680cfc "$target"
objdump -s -j .rodata --start-address=0x4400ef --stop-address=0x440126 "$target"
readelf -rW "$target" | grep -i '0*64df6b8 '
od -An -tx1 -j 105300968 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15b7beca02`), re-decoding lands at `0x646e3e1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 433, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
