# RE-001: map node #115 node/consensus/state.rs:232 conditional call edge


- Component allocation: `consensus`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `node/consensus/state.rs` as an embedded path. At ELF VA `0x2cddc6e` (file offset `0x2cdcc6e`), `488d3de3077703` decodes as `lea rdi, [rip + 0x37707e3]`. Adding the signed displacement `58132451` to the next instruction VA `0x2cddc75` yields `0x644e458`. The decode from the start of FDE range `[0x2cdca20, 0x2cddea5)` reaches that instruction boundary. The FDE itself is at `0x1198608`.


At `0x644e458` (file offset `0x644c458`), an `R_X86_64_RELATIVE` relocation points to `0x43e0ae` in `.rodata`. The next 16 bytes, `1b00000000000000e800000015000000`, decode as a little-endian 64-bit length of 27 and two 32-bit values, 232 and 21. The string's normalized suffix matches `node/consensus/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2cdcb79` is `0x2cddc6e` and the fallthrough is `0x2cdcb7f`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cdcb76` | `4401f0` | `add eax, r14d` |
| `0x2cdcb79` | `0f82ef100000` | `jb 0x2cddc6e` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 58726565 added to `0x2cddc7b` gives the relocation slot `0x64df520`. Its symbol-zero RELATIVE addend is `0x1681da0`. The target's FDE at `0xcc3294` describes `[0x1681da0, 0x1681db9)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2cddc75` | `ff15a5188003` | `call qword ptr [rip + 0x38018a5]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*644e458 '

readelf -rW "$target" | grep -i '0*64df520 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2cdca20 --stop-address=0x2cddc7b "$target"

od -An -tx1 -j 105170016 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43e0ae --stop-address=0x43e0c9 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3de4077703`), re-decoding lands at `0x644e459`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 232, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

