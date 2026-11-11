# RE-001: map node #115 base/short_string.rs:29 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/short_string.rs` as an embedded path. At ELF VA `0x1547205` (file offset `0x1546205`), `488d3d446aeb04` decodes as `lea rdi, [rip + 0x4eb6a44]`. Adding the signed displacement `82537028` to the next instruction VA `0x154720c` yields `0x63fdc50`. The decode from the start of FDE range `[0x1546aa0, 0x15472aa)` reaches that instruction boundary. The FDE itself is at `0x104fde8`.


At `0x63fdc50` (file offset `0x63fbc50`), an `R_X86_64_RELATIVE` relocation points to `0x435643` in `.rodata`. The next 16 bytes, `18000000000000001d00000027000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 29 and 39. The string's normalized suffix matches `base/short_string.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x1546cdc` is `0x1547205` and the fallthrough is `0x1546ce2`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `ja` predicate (`CF = 0 and ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1546cd8` | `48893c24` | `mov qword ptr [rsp], rdi` |
| `0x1546cdc` | `0f8723050000` | `ja 0x1547205` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83461662 added to `0x1547212` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x154720c` | `ff151e86f904` | `call qword ptr [rip + 0x4f9861e]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63fdc50 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x1546aa0 --stop-address=0x1547212 "$target"

od -An -tx1 -j 104840280 -N 16 "$target"

objdump -s -j .rodata --start-address=0x435643 --stop-address=0x43565b "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d456aeb04`), re-decoding lands at `0x63fdc51`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 29, column 39. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

