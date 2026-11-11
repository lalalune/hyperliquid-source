# RE-001: map node #115 base/short_string.rs:52 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/short_string.rs` as an embedded path. At ELF VA `0x15472fc` (file offset `0x15462fc`), `488d3d7d69eb04` decodes as `lea rdi, [rip + 0x4eb697d]`. Adding the signed displacement `82536829` to the next instruction VA `0x1547303` yields `0x63fdc80`. The decode from the start of FDE range `[0x15472b0, 0x1547309)` reaches that instruction boundary. The FDE itself is at `0xcb5d38`.


At `0x63fdc80` (file offset `0x63fbc80`), an `R_X86_64_RELATIVE` relocation points to `0x435643` in `.rodata`. The next 16 bytes, `1800000000000000340000001c000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 52 and 28. The string's normalized suffix matches `base/short_string.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x15472d3` is `0x15472fc` and the fallthrough is `0x15472d5`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15472cf` | `48c1ea38` | `shr rdx, 0x38` |
| `0x15472d3` | `7527` | `jne 0x15472fc` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83461479 added to `0x1547309` gives the relocation slot `0x64df870`. Its symbol-zero RELATIVE addend is `0x1681dc0`. The target's FDE at `0xcc32b0` describes `[0x1681dc0, 0x1681dd9)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1547303` | `ff156785f904` | `call qword ptr [rip + 0x4f98567]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63fdc80 '

readelf -rW "$target" | grep -i '0*64df870 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x15472b0 --stop-address=0x1547309 "$target"

od -An -tx1 -j 104840328 -N 16 "$target"

objdump -s -j .rodata --start-address=0x435643 --stop-address=0x43565b "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d7e69eb04`), re-decoding lands at `0x63fdc81`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 52, column 28. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

