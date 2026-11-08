# RE-001: map node #115 l1/abci/engine.rs:172 conditional call edge


- Component allocation: `abci`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/abci/engine.rs` as an embedded path. At ELF VA `0x2d251d2` (file offset `0x2d241d2`), `4c8d0dcfbe7203` decodes as `lea r9, [rip + 0x372becf]`. Adding the signed displacement `57851599` to the next instruction VA `0x2d251d9` yields `0x64510a8`. The decode from the start of FDE range `[0x2d23610, 0x2d2561c)` reaches that instruction boundary. The FDE itself is at `0x119bce8`.


At `0x64510a8` (file offset `0x644f0a8`), an `R_X86_64_RELATIVE` relocation points to `0x434ab0` in `.rodata`. The next 16 bytes, `1500000000000000ac0000000d000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 172 and 13. The string's normalized suffix matches `l1/abci/engine.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2d23731` is `0x2d251d2` and the fallthrough is `0x2d23737`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d2372e` | `4939c7` | `cmp r15, rax` |
| `0x2d23731` | `0f859b1a0000` | `jne 0x2d251d2` |

## Argument flow


The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 58435621 added to `0x2d251f3` gives the relocation slot `0x64dfa18`. Its symbol-zero RELATIVE addend is `0x167bbb6`. The target's FDE at `0xcc29bc` describes `[0x167bbb6, 0x167bbeb)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d251ed` | `ff1525a87b03` | `call qword ptr [rip + 0x37ba825]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64510a8 '

readelf -rW "$target" | grep -i '0*64dfa18 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2d23610 --stop-address=0x2d251f3 "$target"

od -An -tx1 -j 105181360 -N 16 "$target"

objdump -s -j .rodata --start-address=0x434ab0 --stop-address=0x434ac5 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0dd0be7203`), re-decoding lands at `0x64510a9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 172, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

