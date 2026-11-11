# RE-001: map node #115 l1/qtys/mod.rs:831 conditional call edge


- Component allocation: `assets`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x23cd37c` (file offset `0x23cc37c`), `488d3575240604` decodes as `lea rsi, [rip + 0x4062475]`. Adding the signed displacement `67511413` to the next instruction VA `0x23cd383` yields `0x642f7f8`. The decode from the start of FDE range `[0x23cd2d0, 0x23cd6f5)` reaches that instruction boundary. The FDE itself is at `0x1107574`.


At `0x642f7f8` (file offset `0x642d7f8`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000003f03000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 831 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x23cd30a` is `0x23cd37c` and the fallthrough is `0x23cd30c`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x23cd307` | `4801c8` | `add rax, rcx` |
| `0x23cd30a` | `7270` | `jb 0x23cd37c` |

## Argument flow


The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 68254493 added to `0x23cd38b` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x23cd385` | `ff151d7b1104` | `call qword ptr [rip + 0x4117b1d]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*642f7f8 '

readelf -rW "$target" | grep -i '0*64e4ea8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x23cd2d0 --stop-address=0x23cd38b "$target"

od -An -tx1 -j 105043968 -N 16 "$target"

objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3576240604`), re-decoding lands at `0x642f7f9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 831, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

