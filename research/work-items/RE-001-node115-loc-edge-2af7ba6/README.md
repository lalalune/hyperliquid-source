# RE-001: map node #115 node/consensus/state.rs:210 conditional call edge


- Component allocation: `consensus`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `node/consensus/state.rs` as an embedded path. At ELF VA `0x2af7ba6` (file offset `0x2af6ba6`), `488d3d2b069503` decodes as `lea rdi, [rip + 0x395062b]`. Adding the signed displacement `60098091` to the next instruction VA `0x2af7bad` yields `0x64481d8`. The decode from the start of FDE range `[0x2af77f0, 0x2af8bd3)` reaches that instruction boundary. The FDE itself is at `0x117cafc`.


At `0x64481d8` (file offset `0x64461d8`), an `R_X86_64_RELATIVE` relocation points to `0x43e0ae` in `.rodata`. The next 16 bytes, `1b00000000000000d200000007000000`, decode as a little-endian 64-bit length of 27 and two 32-bit values, 210 and 7. The string's normalized suffix matches `node/consensus/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2af7826` is `0x2af7ba6` and the fallthrough is `0x2af782c`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af7823` | `83f803` | `cmp eax, 3` |
| `0x2af7826` | `0f857a030000` | `jne 0x2af7ba6` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 60725165 added to `0x2af7bb3` gives the relocation slot `0x64e1360`. Its symbol-zero RELATIVE addend is `0x1681e80`. The target's FDE at `0xcc3358` describes `[0x1681e80, 0x1681e99)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af7bad` | `ff15ad979e03` | `call qword ptr [rip + 0x39e97ad]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64481d8 '

readelf -rW "$target" | grep -i '0*64e1360 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2af77f0 --stop-address=0x2af7bb3 "$target"

od -An -tx1 -j 105144800 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43e0ae --stop-address=0x43e0c9 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d2c069503`), re-decoding lands at `0x64481d9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 210, column 7. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

