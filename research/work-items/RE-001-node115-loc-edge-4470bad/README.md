# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:1903 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x4470bad` (file offset `0x446fbad`), `488d3d2cb00102` decodes as `lea rdi, [rip + 0x201b02c]`. Adding the signed displacement `33665068` to the next instruction VA `0x4470bb4` yields `0x648bbe0`. The decode from the start of FDE range `[0x446c200, 0x4472001)` reaches that instruction boundary. The FDE itself is at `0x12a4f24`.


At `0x648bbe0` (file offset `0x6489be0`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `25000000000000006f07000060000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 1903 and 96. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x446ebcd` is `0x4470bad` and the fallthrough is `0x446ebd3`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x446ebca` | `4008d6` | `or sil, dl` |
| `0x446ebcd` | `0f85da1f0000` | `jne 0x4470bad` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 34008182 added to `0x4470bba` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4470bb4` | `ff1576ec0602` | `call qword ptr [rip + 0x206ec76]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*648bbe0 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x446c200 --stop-address=0x4470bba "$target"

od -An -tx1 -j 105421800 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d2db00102`), re-decoding lands at `0x648bbe1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 1903, column 96. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

