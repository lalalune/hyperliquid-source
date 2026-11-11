# RE-001: map node #115 base/c_guard.rs:31 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/c_guard.rs` as an embedded path. At ELF VA `0x1545158` (file offset `0x1544158`), `488d3d118ceb04` decodes as `lea rdi, [rip + 0x4eb8c11]`. Adding the signed displacement `82545681` to the next instruction VA `0x154515f` yields `0x63fdd70`. The decode from the start of FDE range `[0x1544b00, 0x1545388)` reaches that instruction boundary. The FDE itself is at `0x104fb94`.


At `0x63fdd70` (file offset `0x63fbd70`), an `R_X86_64_RELATIVE` relocation points to `0x443c92` in `.rodata`. The next 16 bytes, `13000000000000001f00000009000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 31 and 9. The string's normalized suffix matches `base/c_guard.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x1544ff2` is `0x1545158` and the fallthrough is `0x1544ff8`. The **taken** edge reaches the location load along the instructions below.


The flags come from `cmp rcx, -1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1544fee` | `4883f9ff` | `cmp rcx, -1` |
| `0x1544ff2` | `0f8460010000` | `je 0x1545158` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83469243 added to `0x1545165` gives the relocation slot `0x64df520`. Its symbol-zero RELATIVE addend is `0x1681da0`. The target's FDE at `0xcc3294` describes `[0x1681da0, 0x1681db9)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x154515f` | `ff15bba3f904` | `call qword ptr [rip + 0x4f9a3bb]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63fdd70 '

readelf -rW "$target" | grep -i '0*64df520 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x1544b00 --stop-address=0x1545165 "$target"

od -An -tx1 -j 104840568 -N 16 "$target"

objdump -s -j .rodata --start-address=0x443c92 --stop-address=0x443ca5 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d128ceb04`), re-decoding lands at `0x63fdd71`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 31, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

