# RE-001: map node #115 l1/spot_clearinghouse/cl_trait.rs:376 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/spot_clearinghouse/cl_trait.rs` as an embedded path. At ELF VA `0x3c0d9ec` (file offset `0x3c0c9ec`), `488d3de58c8602` decodes as `lea rdi, [rip + 0x2868ce5]`. Adding the signed displacement `42372325` to the next instruction VA `0x3c0d9f3` yields `0x64766d8`. The decode from the start of FDE range `[0x3c0c8b0, 0x3c0daee)` reaches that instruction boundary. The FDE itself is at `0x124315c`.


At `0x64766d8` (file offset `0x64746d8`), an `R_X86_64_RELATIVE` relocation points to `0x449d41` in `.rodata`. The next 16 bytes, `2500000000000000780100004b000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 376 and 75. The string's normalized suffix matches `l1/spot_clearinghouse/cl_trait.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x3c0d3ef` is `0x3c0d9ec` and the fallthrough is `0x3c0d3f5`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c0d3e7` | `482b9c2438010000` | `sub rbx, qword ptr [rsp + 0x138]` |
| `0x3c0d3ef` | `0f82f7050000` | `jb 0x3c0d9ec` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 42802743 added to `0x3c0d9f9` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c0d9f3` | `ff15371e8d02` | `call qword ptr [rip + 0x28d1e37]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64766d8 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x3c0c8b0 --stop-address=0x3c0d9f9 "$target"

od -An -tx1 -j 105334496 -N 16 "$target"

objdump -s -j .rodata --start-address=0x449d41 --stop-address=0x449d66 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3de68c8602`), re-decoding lands at `0x64766d9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 376, column 75. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

