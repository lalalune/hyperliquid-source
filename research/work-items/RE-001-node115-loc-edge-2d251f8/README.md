# RE-001: map node #115 l1/abci/engine.rs:175 conditional call edge


- Component allocation: `abci`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/abci/engine.rs` as an embedded path. At ELF VA `0x2d251f8` (file offset `0x2d241f8`), `488d15c1be7203` decodes as `lea rdx, [rip + 0x372bec1]`. Adding the signed displacement `57851585` to the next instruction VA `0x2d251ff` yields `0x64510c0`. The decode from the start of FDE range `[0x2d23610, 0x2d2561c)` reaches that instruction boundary. The FDE itself is at `0x119bce8`.


At `0x64510c0` (file offset `0x644f0c0`), an `R_X86_64_RELATIVE` relocation points to `0x434ab0` in `.rodata`. The next 16 bytes, `1500000000000000af00000011000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 175 and 17. The string's normalized suffix matches `l1/abci/engine.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2d2373e` is `0x2d251f8` and the fallthrough is `0x2d23744`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d23737` | `80bb9a0b000003` | `cmp byte ptr [rbx + 0xb9a], 3` |
| `0x2d2373e` | `0f85b41a0000` | `jne 0x2d251f8` |

## Argument flow


The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 58434847 added to `0x2d25211` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2d2520b` | `ff151fa57b03` | `call qword ptr [rip + 0x37ba51f]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64510c0 '

readelf -rW "$target" | grep -i '0*64df730 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2d23610 --stop-address=0x2d25211 "$target"

od -An -tx1 -j 105181384 -N 16 "$target"

objdump -s -j .rodata --start-address=0x434ab0 --stop-address=0x434ac5 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15c2be7203`), re-decoding lands at `0x64510c1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 175, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

