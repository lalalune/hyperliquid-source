# RE-001: map node #115 l1/perp_meta.rs:247 conditional call edge


- Component allocation: `assets`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/perp_meta.rs` as an embedded path. At ELF VA `0x3c432e7` (file offset `0x3c422e7`), `488d3dd2358302` decodes as `lea rdi, [rip + 0x28335d2]`. Adding the signed displacement `42153426` to the next instruction VA `0x3c432ee` yields `0x64768c0`. The decode from the start of FDE range `[0x3c43150, 0x3c432f4)` reaches that instruction boundary. The FDE itself is at `0xe5393c`.


At `0x64768c0` (file offset `0x64748c0`), an `R_X86_64_RELATIVE` relocation points to `0x437df7` in `.rodata`. The next 16 bytes, `1300000000000000f700000048000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 247 and 72. The string's normalized suffix matches `l1/perp_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x3c43240` is `0x3c432e7` and the fallthrough is `0x3c43246`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c4323c` | `493b5748` | `cmp rdx, qword ptr [r15 + 0x48]` |
| `0x3c43240` | `0f83a1000000` | `jae 0x3c432e7` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 42583356 added to `0x3c432f4` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3c432ee` | `ff153cc58902` | `call qword ptr [rip + 0x289c53c]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64768c0 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x3c43150 --stop-address=0x3c432f4 "$target"

od -An -tx1 -j 105334984 -N 16 "$target"

objdump -s -j .rodata --start-address=0x437df7 --stop-address=0x437e0a "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3dd3358302`), re-decoding lands at `0x64768c1`, which fails the exact descriptor-address check.


## Overlap with merged work

Merged RE-001-node115-perp-tier-projection records the descriptor `0x64768c0` as a source location (`l1/src/perp_meta.rs`, line 247, column 72) with xref `0x3c432e7`, and lists the call pc `0x3c432ee` (rip-slot, slot `0x64df830`) in its function record; merged RE-001-perp-tier-selector-115 lists the same site and call in its proof. Neither pins the `jae` guard at `0x3c43240`, the guard-to-site edge, the `rdi` argument flow into the call, nor the callee `0x1680c10` — the edge itself is new ground.

## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 247, column 72. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

