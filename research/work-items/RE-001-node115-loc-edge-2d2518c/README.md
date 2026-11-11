# RE-001: map node #115 l1/abci/engine.rs:170 conditional call edge


- Component allocation: `abci`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/abci/engine.rs` as an embedded path. At ELF VA `0x2d2518c` (file offset `0x2d2418c`), `4c8d0de5be7203` decodes as `lea r9, [rip + 0x372bee5]`. Adding the signed displacement `57851621` to the next instruction VA `0x2d25193` yields `0x6451078`. The decode from the start of FDE range `[0x2d23610, 0x2d2561c)` reaches that instruction boundary. The FDE itself is at `0x119bce8`.


At `0x6451078` (file offset `0x644f078`), an `R_X86_64_RELATIVE` relocation points to `0x434ab0` in `.rodata`. The next 16 bytes, `1500000000000000aa0000000d000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 170 and 13. The string's normalized suffix matches `l1/abci/engine.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2d236e4` is `0x2d2518c` and the fallthrough is `0x2d236ea`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d236e1` | `4839f7` | `cmp rdi, rsi` |
| `0x2d236e4` | `0f85a21a0000` | `jne 0x2d2518c` |

## Argument flow


The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 58470190 added to `0x2d251aa` gives the relocation slot `0x64e80d8`. Its symbol-zero RELATIVE addend is `0x5a5d384`. The target's FDE at `0xfc49c8` describes `[0x5a5d384, 0x5a5d3b7)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d251a4` | `ff152e2f7c03` | `call qword ptr [rip + 0x37c2f2e]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6451078 '

readelf -rW "$target" | grep -i '0*64e80d8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2d23610 --stop-address=0x2d251aa "$target"

od -An -tx1 -j 105181312 -N 16 "$target"

objdump -s -j .rodata --start-address=0x434ab0 --stop-address=0x434ac5 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0de6be7203`), re-decoding lands at `0x6451079`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 170, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

