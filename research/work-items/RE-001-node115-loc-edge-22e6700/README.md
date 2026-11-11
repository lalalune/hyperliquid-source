# RE-001: map node #115 l1/spot_clearinghouse/types.rs:159 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/spot_clearinghouse/types.rs` as an embedded path. At ELF VA `0x22e6700` (file offset `0x22e5700`), `488d3d89ff1804` decodes as `lea rdi, [rip + 0x418ff89]`. Adding the signed displacement `68747145` to the next instruction VA `0x22e6707` yields `0x6476690`. The decode from the start of FDE range `[0x22e6390, 0x22e6785)` reaches that instruction boundary. The FDE itself is at `0xcfa3c8`.


At `0x6476690` (file offset `0x6474690`), an `R_X86_64_RELATIVE` relocation points to `0x444e61` in `.rodata`. The next 16 bytes, `22000000000000009f00000032000000`, decode as a little-endian 64-bit length of 34 and two 32-bit values, 159 and 50. The string's normalized suffix matches `l1/spot_clearinghouse/types.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x22e6477` is `0x22e6700` and the fallthrough is `0x22e647d`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e6474` | `4c29f8` | `sub rax, r15` |
| `0x22e6477` | `0f8283020000` | `jb 0x22e6700` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 69177635 added to `0x22e670d` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e6707` | `ff1523911f04` | `call qword ptr [rip + 0x41f9123]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6476690 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x22e6390 --stop-address=0x22e670d "$target"

od -An -tx1 -j 105334424 -N 16 "$target"

objdump -s -j .rodata --start-address=0x444e61 --stop-address=0x444e83 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d8aff1804`), re-decoding lands at `0x6476691`, which fails the exact descriptor-address check.


## Interpretation and limits


Overlap note: merged RE-001-node115-spot-record-update-order records this same descriptor `0x6476690` as a source location (types.rs:159:50) with xref `0x3bfabda`, a different load site in a different function; it pins neither the lea site `0x22e6700`, the `jb` guard at `0x22e6477`, nor the indirect call at `0x22e6707` — the edge itself is new ground. The same enclosing FDE also holds the merged-adjacent qtys/mod.rs:835 edge (PR #4856) at `0x22e66d1`, a distinct location in the same function, not a duplicate.

The layout is consistent with Rust source-location metadata for line 159, column 50. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

