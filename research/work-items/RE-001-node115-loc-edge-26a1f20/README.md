# RE-001: map node #115 base/u.rs:104 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x26a1f20` (file offset `0x26a0f20`), `4c8d0d6956d903` decodes as `lea r9, [rip + 0x3d95669]`. Adding the signed displacement `64575081` to the next instruction VA `0x26a1f27` yields `0x6437590`. The decode from the start of FDE range `[0x26a1e90, 0x26a1f6a)` reaches that instruction boundary. The FDE itself is at `0x112c3d4`.


At `0x6437590` (file offset `0x6435590`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000006800000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 104 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x26a1eb3` is `0x26a1f20` and the fallthrough is `0x26a1eb5`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26a1eb0` | `4839c8` | `cmp rax, rcx` |
| `0x26a1eb3` | `756b` | `jne 0x26a1f20` |

## Argument flow


The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 65264351 added to `0x26a1f39` gives the relocation slot `0x64dfa18`. Its symbol-zero RELATIVE addend is `0x167bbb6`. The target's FDE at `0xcc29bc` describes `[0x167bbb6, 0x167bbeb)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26a1f33` | `ff15dfdae303` | `call qword ptr [rip + 0x3e3dadf]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6437590 '

readelf -rW "$target" | grep -i '0*64dfa18 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x26a1e90 --stop-address=0x26a1f39 "$target"

od -An -tx1 -j 105076120 -N 16 "$target"

objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d6a56d903`), re-decoding lands at `0x6437591`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 104, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: merged RE-009-abci-freeze-snapshot-115 records this address range as a byte window (`windows.tsv` row `join_mismatch` at 0x26a1f20, raw bytes including the lea) and the guard as a `conditional_short` transfer (`transfers.tsv` row `join_count_mismatch` at 0x26a1eb3), but pins neither the descriptor 0x6437590, the `base/u.rs:104` source location, the `jne` predicate, nor the indirect call at 0x26a1f33 — the edge itself is new ground.

