# RE-001: map node #115 base/time.rs:71 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/time.rs` as an embedded path. At ELF VA `0x15028d4` (file offset `0x15018d4`), `488d3db5bdef04` decodes as `lea rdi, [rip + 0x4efbdb5]`. Adding the signed displacement `82820533` to the next instruction VA `0x15028db` yields `0x63fe690`. The decode from the start of FDE range `[0x15027d0, 0x15028e1)` reaches that instruction boundary. The FDE itself is at `0xcb1430`.


At `0x63fe690` (file offset `0x63fc690`), an `R_X86_64_RELATIVE` relocation points to `0x44c66e` in `.rodata`. The next 16 bytes, `10000000000000004700000037000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 71 and 55. The string's normalized suffix matches `base/time.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x150286e` is `0x15028d4` and the fallthrough is `0x1502870`. The **taken** edge reaches the location load along the instructions below.


The flags come from `test eax, eax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x150286c` | `85c0` | `test eax, eax` |
| `0x150286e` | `7464` | `je 0x15028d4` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83742543 added to `0x15028e1` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15028db` | `ff154fcffd04` | `call qword ptr [rip + 0x4fdcf4f]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63fe690 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x15027d0 --stop-address=0x15028e1 "$target"

od -An -tx1 -j 104842904 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44c66e --stop-address=0x44c67e "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3db6bdef04`), re-decoding lands at `0x63fe691`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 71, column 55. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

