# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:214 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x4476d95` (file offset `0x4475d95`), `488d3d444d0102` decodes as `lea rdi, [rip + 0x2014d44]`. Adding the signed displacement `33639748` to the next instruction VA `0x4476d9c` yields `0x648bae0`. The decode from the start of FDE range `[0x4473d10, 0x44770e5)` reaches that instruction boundary. The FDE itself is at `0x12a5080`.


At `0x648bae0` (file offset `0x6489ae0`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `2500000000000000d600000043000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 214 and 67. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x447468a` is `0x4476d95` and the fallthrough is `0x4474690`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4474686` | `483b5318` | `cmp rdx, qword ptr [rbx + 0x18]` |
| `0x447468a` | `0f8305270000` | `jae 0x4476d95` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 33983118 added to `0x4476da2` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4476d9c` | `ff158e8a0602` | `call qword ptr [rip + 0x2068a8e]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*648bae0 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x4473d10 --stop-address=0x4476da2 "$target"

od -An -tx1 -j 105421544 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d454d0102`), re-decoding lands at `0x648bae1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 214, column 67. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

