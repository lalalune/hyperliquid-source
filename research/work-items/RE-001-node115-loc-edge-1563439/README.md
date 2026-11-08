# RE-001: map node #115 base/u.rs:512 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x1563439` (file offset `0x1562439`), `488d0da0b0e904` decodes as `lea rcx, [rip + 0x4e9b0a0]`. Adding the signed displacement `82423968` to the next instruction VA `0x1563440` yields `0x63fe4e0`. The decode from the start of FDE range `[0x1562670, 0x1563a5c)` reaches that instruction boundary. The FDE itself is at `0x1051428`.


At `0x63fe4e0` (file offset `0x63fc4e0`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d00000000000000000200000f000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 512 and 15. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x156316e` is `0x1563439` and the fallthrough is `0x1563174`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x156316b` | `80fa01` | `cmp dl, 1` |
| `0x156316e` | `0f85c5020000` | `jne 0x1563439` |

## Argument flow


The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 83351050 added to `0x156350e` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1563508` | `ff150ad6f704` | `call qword ptr [rip + 0x4f7d60a]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63fe4e0 '

readelf -rW "$target" | grep -i '0*64e0b18 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x1562670 --stop-address=0x156350e "$target"

od -An -tx1 -j 104842472 -N 16 "$target"

objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0da1b0e904`), re-decoding lands at `0x63fe4e1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 512, column 15. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: the guard instruction and the lea site also appear in the raw disassembly export of merged RE-014-host-ip-gates-115 (`owners.gnu.txt`), which pins a different edge in the same region (`base/u.rs:457`); the descriptor binding for line 512 is not recorded there.

