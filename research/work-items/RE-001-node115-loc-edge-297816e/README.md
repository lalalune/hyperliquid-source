# RE-001: map node #115 info_server/abci_state_info_handler.rs:81 conditional call edge


- Component allocation: `info-api`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `info_server/abci_state_info_handler.rs` as an embedded path. At ELF VA `0x297816e` (file offset `0x297716e`), `488d3d83acac03` decodes as `lea rdi, [rip + 0x3acac83]`. Adding the signed displacement `61648003` to the next instruction VA `0x2978175` yields `0x6442df8`. The decode from the start of FDE range `[0x29780e0, 0x2978192)` reaches that instruction boundary. The FDE itself is at `0x115dac8`.


At `0x6442df8` (file offset `0x6440df8`), an `R_X86_64_RELATIVE` relocation points to `0x432b83` in `.rodata`. The next 16 bytes, `2a00000000000000510000000c000000`, decode as a little-endian 64-bit length of 42 and two 32-bit values, 81 and 12. The string's normalized suffix matches `info_server/abci_state_info_handler.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x29780ed` is `0x297816e` and the fallthrough is `0x29780ef`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x29780eb` | `85c0` | `test eax, eax` |
| `0x29780ed` | `757f` | `jne 0x297816e` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 62296552 added to `0x2978180` gives the relocation slot `0x64e1368`. Its symbol-zero RELATIVE addend is `0x1681e60`. The target's FDE at `0xcc333c` describes `[0x1681e60, 0x1681e79)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x297817a` | `ff15e891b603` | `call qword ptr [rip + 0x3b691e8]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6442df8 '

readelf -rW "$target" | grep -i '0*64e1368 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x29780e0 --stop-address=0x2978180 "$target"

od -An -tx1 -j 105123328 -N 16 "$target"

objdump -s -j .rodata --start-address=0x432b83 --stop-address=0x432bad "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d84acac03`), re-decoding lands at `0x6442df9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 81, column 12. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: merged `RE-001-node115-loc-edge-2978117` records this same guard instruction (`jne` at `0x29780ed`) and its taken target `0x297816e`, but pins the **fallthrough** edge to the `info_server/abci_state_info_handler.rs:82` location load at `0x2978117` (descriptor `0x6442de0`) — it pins neither this taken edge, the `:81` descriptor `0x6442df8`, nor the call at `0x297817a`. The edge itself is new ground.

