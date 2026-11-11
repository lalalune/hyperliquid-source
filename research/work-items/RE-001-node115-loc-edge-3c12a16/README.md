# RE-001: map node #115 l1/abci/state.rs:82 conditional call edge


- Component allocation: `abci`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/abci/state.rs` as an embedded path. At ELF VA `0x3c12a16` (file offset `0x3c11a16`), `4c8d0d733d8602` decodes as `lea r9, [rip + 0x2863d73]`. Adding the signed displacement `42351987` to the next instruction VA `0x3c12a1d` yields `0x6476790`. The decode from the start of FDE range `[0x3c12800, 0x3c12af5)` reaches that instruction boundary. The FDE itself is at `0x1243300`.


At `0x6476790` (file offset `0x6474790`), an `R_X86_64_RELATIVE` relocation points to `0x443168` in `.rodata`. The next 16 bytes, `14000000000000005200000015000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 82 and 21. The string's normalized suffix matches `l1/abci/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x3c128d7` is `0x3c12a16` and the fallthrough is `0x3c128dd`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c128d4` | `4c39f8` | `cmp rax, r15` |
| `0x3c128d7` | `0f8539010000` | `jne 0x3c12a16` |

## Argument flow


The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 42791991 added to `0x3c12a31` gives the relocation slot `0x64e1e68`. Its symbol-zero RELATIVE addend is `0x167bbeb`. The target's FDE at `0xcc29d8` describes `[0x167bbeb, 0x167bc20)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c12a2b` | `ff1537f48c02` | `call qword ptr [rip + 0x28cf437]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6476790 '

readelf -rW "$target" | grep -i '0*64e1e68 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x3c12800 --stop-address=0x3c12a31 "$target"

od -An -tx1 -j 105334680 -N 16 "$target"

objdump -s -j .rodata --start-address=0x443168 --stop-address=0x44317c "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d743d8602`), re-decoding lands at `0x6476791`, which fails the exact descriptor-address check.


## Overlap with merged work

Merged RE-017-abci-loader-handoff-115 records the `jne` guard at `0x3c128d7` and its taken target `0x3c12a16` (`loader_height_mismatch` in edges.tsv), the LEA and descriptor `0x6476790` (`state_mismatch` in references.tsv), and narrates the mismatch reaching `state.rs:82:21`. It pins neither the indirect call at `0x3c12a2b` (slot `0x64e1e68` → `0x167bbeb`), nor the `r9` argument flow into that call — the edge itself is new ground.

## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 82, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

