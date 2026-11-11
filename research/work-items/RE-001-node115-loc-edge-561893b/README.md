# RE-001: map node #115 l1/abci/state.rs:340 conditional call edge

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/abci/state.rs` as an embedded path. At ELF VA `0x561893b` (file offset `0x561793b`), `4c8d0d1e19e900` decodes as `lea r9, [rip + 0xe9191e]`. Adding the signed displacement `15276318` to the next instruction VA `0x5618942` yields `0x64aa260`. The decode from the start of FDE range `[0x5618890, 0x5618986)` reaches that instruction boundary. The FDE itself is at `0x135f858`.

At `0x64aa260` (file offset `0x64a8260`), an `R_X86_64_RELATIVE` relocation points to `0x443168` in `.rodata`. The next 16 bytes, `14000000000000005401000015000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 340 and 21. The string's normalized suffix matches `l1/abci/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x56188be` is `0x561893b` and the fallthrough is `0x56188c0`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rsi, rcx`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x56188bb` | `4839ce` | `cmp rsi, rcx` |
| `0x56188be` | `757b` | `jne 0x561893b` |

## Argument flow

The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 15495362 added to `0x5618956` gives the relocation slot `0x64dfa18`. Its symbol-zero RELATIVE addend is `0x167bbb6`. The target's FDE at `0xcc29bc` describes `[0x167bbb6, 0x167bbeb)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5618942` | `488d742420` | `lea rsi, [rsp + 0x20]` |
| `0x5618947` | `488d542428` | `lea rdx, [rsp + 0x28]` |
| `0x561894c` | `31ff` | `xor edi, edi` |
| `0x561894e` | `31c9` | `xor ecx, ecx` |
| `0x5618950` | `ff15c270ec00` | `call qword ptr [rip + 0xec70c2]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa260 '
readelf -rW "$target" | grep -i '0*64dfa18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5618890 --stop-address=0x5618956 "$target"
od -An -tx1 -j 105546344 -N 16 "$target"
objdump -s -j .rodata --start-address=0x443168 --stop-address=0x44317c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d1f19e900`), re-decoding lands at `0x64aa261`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 340, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
