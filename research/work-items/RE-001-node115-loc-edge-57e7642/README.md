# RE-001: map node #115 node/consensus/latency_samplers.rs:38 conditional call edge


- Component allocation: `consensus`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `node/consensus/latency_samplers.rs` as an embedded path. At ELF VA `0x57e7642` (file offset `0x57e6642`), `488d154796cc00` decodes as `lea rdx, [rip + 0xcc9647]`. Adding the signed displacement `13407815` to the next instruction VA `0x57e7649` yields `0x64b0c90`. The decode from the start of FDE range `[0x57e73d0, 0x57e7715)` reaches that instruction boundary. The FDE itself is at `0x137b2c8`.


At `0x64b0c90` (file offset `0x64aec90`), an `R_X86_64_RELATIVE` relocation points to `0x439f0b` in `.rodata`. The next 16 bytes, `26000000000000002600000015000000`, decode as a little-endian 64-bit length of 38 and two 32-bit values, 38 and 21. The string's normalized suffix matches `node/consensus/latency_samplers.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x57e7631` is `0x57e7642` and the fallthrough is `0x57e7633`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57e762c` | `807c240e00` | `cmp byte ptr [rsp + 0xe], 0` |
| `0x57e7631` | `740f` | `je 0x57e7642` |

## Argument flow


The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 13605296 added to `0x57e7660` gives the relocation slot `0x64e1010`. Its symbol-zero RELATIVE addend is `0x1547530`. The target's FDE at `0x104fe54` describes `[0x1547530, 0x1548ba3)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57e765a` | `ff15b099cf00` | `call qword ptr [rip + 0xcf99b0]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64b0c90 '

readelf -rW "$target" | grep -i '0*64e1010 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x57e73d0 --stop-address=0x57e7660 "$target"

od -An -tx1 -j 105573528 -N 16 "$target"

objdump -s -j .rodata --start-address=0x439f0b --stop-address=0x439f31 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d154896cc00`), re-decoding lands at `0x64b0c91`, which fails the exact descriptor-address check.


## Overlap note


Merged `RE-001-node115-location-57e7642` pins this same lea site (`0x57e7642`) and descriptor (`0x64b0c90`) as a source-location anchor for `latency_samplers.rs:38`, and states the consumer of the loaded pointer remains unresolved. It pins neither the `je` guard at `0x57e7631`, the `rdx` trace, nor the call at `0x57e765a` — the edge itself is new ground; this packet supplies the next step that anchor packet names.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 38, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

