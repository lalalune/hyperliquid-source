# RE-001: map node #115 l1/clearinghouse/margin_table.rs:139 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/clearinghouse/margin_table.rs` as an embedded path. At ELF VA `0x38b4f6b` (file offset `0x38b3f6b`), `488d3d0e94bb02` decodes as `lea rdi, [rip + 0x2bb940e]`. Adding the signed displacement `45847566` to the next instruction VA `0x38b4f72` yields `0x646e380`. The decode from the start of FDE range `[0x38b4e20, 0x38b4f7a)` reaches that instruction boundary. The FDE itself is at `0x121dc1c`.


At `0x646e380` (file offset `0x646c380`), an `R_X86_64_RELATIVE` relocation points to `0x4441e4` in `.rodata`. The next 16 bytes, `24000000000000008b00000039000000`, decode as a little-endian 64-bit length of 36 and two 32-bit values, 139 and 57. The string's normalized suffix matches `l1/clearinghouse/margin_table.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x38b4ee1` is `0x38b4f6b` and the fallthrough is `0x38b4ee7`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38b4edc` | `4883781800` | `cmp qword ptr [rax + 0x18], 0` |
| `0x38b4ee1` | `0f8484000000` | `je 0x38b4f6b` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 46311608 added to `0x38b4f78` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38b4f72` | `ff15b8a8c202` | `call qword ptr [rip + 0x2c2a8b8]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*646e380 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x38b4e20 --stop-address=0x38b4f78 "$target"

od -An -tx1 -j 105300872 -N 16 "$target"

objdump -s -j .rodata --start-address=0x4441e4 --stop-address=0x444208 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d0f94bb02`), re-decoding lands at `0x646e381`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 139, column 57. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: merged `RE-001-node115-location-38b4f6b` anchors this same location load (lea site `0x38b4f6b`, descriptor `0x646e380`, margin_table.rs:139:57) but explicitly leaves the consumer unresolved ("the eventual consumer of the loaded pointer remain unresolved") and pins neither the `je` guard at `0x38b4ee1`, nor the indirect call at `0x38b4f72`, nor its callee — the conditional call edge itself is new ground here.

