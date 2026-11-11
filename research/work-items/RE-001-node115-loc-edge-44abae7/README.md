# RE-001: map node #115 l1/vault/mod.rs:623 conditional call edge


- Component allocation: `vaults`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/vault/mod.rs` as an embedded path. At ELF VA `0x44abae7` (file offset `0x44aaae7`), `488d3d8206fe01` decodes as `lea rdi, [rip + 0x1fe0682]`. Adding the signed displacement `33425026` to the next instruction VA `0x44abaee` yields `0x648c170`. The decode from the start of FDE range `[0x44ab4a0, 0x44abfaf)` reaches that instruction boundary. The FDE itself is at `0x12a6324`.


At `0x648c170` (file offset `0x648a170`), an `R_X86_64_RELATIVE` relocation points to `0x43e326` in `.rodata`. The next 16 bytes, `13000000000000006f02000047000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 623 and 71. The string's normalized suffix matches `l1/vault/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x44abad7` is `0x44abae7` and the fallthrough is `0x44abad9`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44abacf` | `660f2e0539d5fafb` | `ucomisd xmm0, qword ptr [rip - 0x4052ac7]` |
| `0x44abad7` | `740e` | `je 0x44abae7` |

## Argument flow


The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 33766716 added to `0x44abaf4` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44abaee` | `ff153c3d0302` | `call qword ptr [rip + 0x2033d3c]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*648c170 '

readelf -rW "$target" | grep -i '0*64df830 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x44ab4a0 --stop-address=0x44abaf4 "$target"

od -An -tx1 -j 105423224 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43e326 --stop-address=0x43e339 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d8306fe01`), re-decoding lands at `0x648c171`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 623, column 71. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

