# RE-001: map node #115 l1/clearinghouse/impl_first_dex.rs:69 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/clearinghouse/impl_first_dex.rs` as an embedded path. At ELF VA `0x448308e` (file offset `0x448208e`), `488d3df38c0002` decodes as `lea rdi, [rip + 0x2008cf3]`. Adding the signed displacement `33590515` to the next instruction VA `0x4483095` yields `0x648bd88`. The decode from the start of FDE range `[0x4482950, 0x44830f3)` reaches that instruction boundary. The FDE itself is at `0x12a55f8`.


At `0x648bd88` (file offset `0x6489d88`), an `R_X86_64_RELATIVE` relocation points to `0x437e0b` in `.rodata`. The next 16 bytes, `26000000000000004500000058000000`, decode as a little-endian 64-bit length of 38 and two 32-bit values, 69 and 88. The string's normalized suffix matches `l1/clearinghouse/impl_first_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x4482f96` is `0x448308e` and the fallthrough is `0x4482f9c`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `js` predicate (`SF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4482f93` | `4885d2` | `test rdx, rdx` |
| `0x4482f96` | `0f88f2000000` | `js 0x448308e` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 33933205 added to `0x448309b` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4483095` | `ff1595c70502` | `call qword ptr [rip + 0x205c795]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*648bd88 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x4482950 --stop-address=0x448309b "$target"

od -An -tx1 -j 105422224 -N 16 "$target"

objdump -s -j .rodata --start-address=0x437e0b --stop-address=0x437e31 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3df48c0002`), re-decoding lands at `0x648bd89`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 69, column 88. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

