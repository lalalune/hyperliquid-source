# RE-001: map node #115 l1/clearinghouse/clearinghouse.rs:2383 conditional call edge


- Component allocation: `risk`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/clearinghouse/clearinghouse.rs` as an embedded path. At ELF VA `0x42037d2` (file offset `0x42027d2`), `488d3def062802` decodes as `lea rdi, [rip + 0x22806ef]`. Adding the signed displacement `36177647` to the next instruction VA `0x42037d9` yields `0x6483ec8`. The decode from the start of FDE range `[0x4203320, 0x42038d3)` reaches that instruction boundary. The FDE itself is at `0xe88f64`.


At `0x6483ec8` (file offset `0x6481ec8`), an `R_X86_64_RELATIVE` relocation points to `0x44f75e` in `.rodata`. The next 16 bytes, `25000000000000004f09000052000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 2383 and 82. The string's normalized suffix matches `l1/clearinghouse/clearinghouse.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x42037c1` is `0x42037d2` and the fallthrough is `0x42037c3`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jo` predicate (`OF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x42037bc` | `4c8b742408` | `mov r14, qword ptr [rsp + 8]` |
| `0x42037c1` | `700f` | `jo 0x42037d2` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 36552785 added to `0x42037df` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x42037d9` | `ff1551c02d02` | `call qword ptr [rip + 0x22dc051]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6483ec8 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x4203320 --stop-address=0x42037df "$target"

od -An -tx1 -j 105389776 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44f75e --stop-address=0x44f783 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3df0062802`), re-decoding lands at `0x6483ec9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 2383, column 82. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.


## Overlap note

Merged `RE-001-node115-position-sign-transition-value` lists the call pc `0x42037d9` in its calls census and records the descriptor `0x6483ec8` only as a RELATIVE-relocation control and a raw byte record (line 2383 is encoded in the raw tail, not named as a source location). The guard `0x42037c1` and the site `0x42037d2` appear only as lines in its whole-function disassembly exports (`transition.gnu.txt` / `transition.llvm.txt`); its README never names `clearinghouse.rs:2383`. It pins neither the `jo` guard, the guard-to-site edge, the `rdi` argument flow, nor the callee `0x1680c10` — the edge itself is new ground.
