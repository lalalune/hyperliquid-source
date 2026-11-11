# RE-001: map node #115 l1/hyperliquidity.rs:360 conditional call edge


- Component allocation: `l1-shared`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/hyperliquidity.rs` as an embedded path. At ELF VA `0x38bca3f` (file offset `0x38bba3f`), `488d3d821abb02` decodes as `lea rdi, [rip + 0x2bb1a82]`. Adding the signed displacement `45816450` to the next instruction VA `0x38bca46` yields `0x646e4c8`. The decode from the start of FDE range `[0x38bc000, 0x38bca91)` reaches that instruction boundary. The FDE itself is at `0x121e084`.


At `0x646e4c8` (file offset `0x646c4c8`), an `R_X86_64_RELATIVE` relocation points to `0x4481d6` in `.rodata`. The next 16 bytes, `1800000000000000680100001d000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 360 and 29. The string's normalized suffix matches `l1/hyperliquidity.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x38bc5e2` is `0x38bca3f` and the fallthrough is `0x38bc5e8`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bc5df` | `4885f6` | `test rsi, rsi` |
| `0x38bc5e2` | `0f8457040000` | `je 0x38bca3f` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 46280164 added to `0x38bca4c` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38bca46` | `ff15e42dc202` | `call qword ptr [rip + 0x2c22de4]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*646e4c8 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x38bc000 --stop-address=0x38bca4c "$target"

od -An -tx1 -j 105301200 -N 16 "$target"

objdump -s -j .rodata --start-address=0x4481d6 --stop-address=0x4481ee "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d831abb02`), re-decoding lands at `0x646e4c9`, which fails the exact descriptor-address check.


Overlap note: merged RE-001-node115-location-38bca3f anchors the same lea site and descriptor but explicitly leaves the consumer unresolved and pins neither the je guard, the indirect call, nor the callee — the edge itself is new ground (same shared-location precedent as #4895).

## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 360, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

