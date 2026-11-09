# RE-001: map node #115 l1/qtys/impl_ntl.rs:683 conditional call edge


- Component allocation: `assets`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/qtys/impl_ntl.rs` as an embedded path. At ELF VA `0x2a83832` (file offset `0x2a82832`), `488d35c701a103` decodes as `lea rsi, [rip + 0x3a101c7]`. Adding the signed displacement `60883399` to the next instruction VA `0x2a83839` yields `0x6493a00`. The decode from the start of FDE range `[0x2a82ea0, 0x2a83955)` reaches that instruction boundary. The FDE itself is at `0x116f34c`.


At `0x6493a00` (file offset `0x6491a00`), an `R_X86_64_RELATIVE` relocation points to `0x43df4b` in `.rodata`. The next 16 bytes, `1700000000000000ab02000001000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 683 and 1. The string's normalized suffix matches `l1/qtys/impl_ntl.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2a83745` is `0x2a83832` and the fallthrough is `0x2a8374b`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jo` predicate (`OF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a83742` | `4801d0` | `add rax, rdx` |
| `0x2a83745` | `0f80e7000000` | `jo 0x2a83832` |

## Argument flow


The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 61216356 added to `0x2a83844` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a8383e` | `ff156416a603` | `call qword ptr [rip + 0x3a61664]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6493a00 '

readelf -rW "$target" | grep -i '0*64e4ea8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2a82ea0 --stop-address=0x2a83844 "$target"

od -An -tx1 -j 105454088 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43df4b --stop-address=0x43df62 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35c801a103`), re-decoding lands at `0x6493a01`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 683, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

