# RE-001: map node #115 base/log/handle.rs:144 conditional call edge


- Component allocation: `foundation`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `base/log/handle.rs` as an embedded path. At ELF VA `0x15a5c09` (file offset `0x15a4c09`), `488d3d389fe504` decodes as `lea rdi, [rip + 0x4e59f38]`. Adding the signed displacement `82157368` to the next instruction VA `0x15a5c10` yields `0x63ffb48`. The decode from the start of FDE range `[0x15a3b90, 0x15a6509)` reaches that instruction boundary. The FDE itself is at `0x105530c`.


At `0x63ffb48` (file offset `0x63fdb48`), an `R_X86_64_RELATIVE` relocation points to `0x43ab16` in `.rodata`. The next 16 bytes, `16000000000000009000000054000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 144 and 84. The string's normalized suffix matches `base/log/handle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x15a4d95` is `0x15a5c09` and the fallthrough is `0x15a4d9b`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15a4d92` | `4885c0` | `test rax, rax` |
| `0x15a4d95` | `0f846e0e0000` | `je 0x15a5c09` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 83074074 added to `0x15a5c16` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15a5c10` | `ff151a9cf304` | `call qword ptr [rip + 0x4f39c1a]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63ffb48 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x15a3b90 --stop-address=0x15a5c16 "$target"

od -An -tx1 -j 104848208 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43ab16 --stop-address=0x43ab2c "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d399fe504`), re-decoding lands at `0x63ffb49`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 144, column 84. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: merged RE-015-node115-second-structure-readers records this same descriptor `0x63ffb48` as a panic-arm location static for `base/src/log/handle.rs` lines 144/145, but pins neither the lea site `0x15a5c09`, the `je` guard at `0x15a4d95`, nor the indirect call at `0x15a5c10` — the conditional call edge itself is new ground here.

