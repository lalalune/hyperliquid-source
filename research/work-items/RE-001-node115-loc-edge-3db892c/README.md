# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:179 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x3db892c` (file offset `0x3db792c`), `488d3df5316d02` decodes as `lea rdi, [rip + 0x26d31f5]`. Adding the signed displacement `40710645` to the next instruction VA `0x3db8933` yields `0x648bb28`. The decode from the start of FDE range `[0x3db8470, 0x3db8983)` reaches that instruction boundary. The FDE itself is at `0x126bde4`.


At `0x648bb28` (file offset `0x6489b28`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `2500000000000000b300000062000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 179 and 98. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x3db86f6` is `0x3db892c` and the fallthrough is `0x3db86fc`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jo` predicate (`OF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3db86f2` | `4d0faff5` | `imul r14, r13` |
| `0x3db86f6` | `0f8030020000` | `jo 0x3db892c` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 41053943 added to `0x3db8939` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3db8933` | `ff15f76e7202` | `call qword ptr [rip + 0x2726ef7]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*648bb28 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x3db8470 --stop-address=0x3db8939 "$target"

od -An -tx1 -j 105421616 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3df6316d02`), re-decoding lands at `0x648bb29`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 179, column 98. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.


## Overlap note

Merged `RE-007-node115-clearinghouse-ntl-ratio` records this same descriptor `0x648bb28` as a source location (`l1/src/clearinghouse/clearinghouse.rs:179:98`) with xrefs `0x44dd116` and `0x3db892c`, and lists the call pc `0x3db8933` in its calls census. It narrates only the first use at `0x44dd116`; its README states the second use at `0x3db892c` is "retained in the export and [is] not given semantics here". It pins neither the `jo` guard at `0x3db86f6`, the guard-to-site edge, the `rdi` argument flow, nor the callee `0x1680c10` as the consumer of this site — the edge itself is new ground.
