# RE-001: map node #115 l1/qtys/mod.rs:835 conditional call edge


- Component allocation: `assets`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x22e66d1` (file offset `0x22e56d1`), `488d35880d1a04` decodes as `lea rsi, [rip + 0x41a0d88]`. Adding the signed displacement `68816264` to the next instruction VA `0x22e66d8` yields `0x6487460`. The decode from the start of FDE range `[0x22e6390, 0x22e6785)` reaches that instruction boundary. The FDE itself is at `0xcfa3c8`.


At `0x6487460` (file offset `0x6485460`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000004303000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 835 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x22e6465` is `0x22e66d1` and the fallthrough is `0x22e646b`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jb` predicate (`CF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e6462` | `4c01fb` | `add rbx, r15` |
| `0x22e6465` | `0f8266020000` | `jb 0x22e66d1` |

## Argument flow


The LEA writes `rsi`. The trace follows the unchanged value to the call. One instruction intervenes between the load and the call — `xor edi, edi` at `0x22e66d8` (`31ff`) — which writes `edi`, not the argument register `rsi`, so the loaded descriptor reaches the call unchanged. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 69199816 added to `0x22e66e0` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e66da` | `ff15c8e71f04` | `call qword ptr [rip + 0x41fe7c8]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6487460 '

readelf -rW "$target" | grep -i '0*64e4ea8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x22e6390 --stop-address=0x22e66e0 "$target"

od -An -tx1 -j 105403496 -N 16 "$target"

objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35890d1a04`), re-decoding lands at `0x6487461`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 835, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: descriptor `0x6487460` is a shared panic-location literal for `l1/src/qtys/mod.rs:835` — it is loaded at several other sites in other functions (e.g. `0x2bb672a`, `0x2bb6756`, `0x2bb6793`, `0x2bb67ba`, recorded in merged `RE-001-node115-bole-three-attempt-selection`'s disassembly export, plus `0x38daf23` and `0x3bf3935` in the outcome-projection packets) and cited as a literal in those packets' `LITERALS` records — but none of them pins this edge: the lea site `0x22e66d1`, the `jb` guard at `0x22e6465`, and the indirect call at `0x22e66da` appear in no merged work item. The edge itself is new ground.

