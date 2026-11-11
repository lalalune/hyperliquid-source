# RE-001: map node #115 l1/abci/abci_hash.rs:28 conditional call edge


- Component allocation: `abci`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/abci/abci_hash.rs` as an embedded path. At ELF VA `0x2bb3897` (file offset `0x2bb2897`), `488d15229d8903` decodes as `lea rdx, [rip + 0x3899d22]`. Adding the signed displacement `59350306` to the next instruction VA `0x2bb389e` yields `0x644d5c0`. The decode from the start of FDE range `[0x2bb37c0, 0x2bb39c3)` reaches that instruction boundary. The FDE itself is at `0x1187a34`.


At `0x644d5c0` (file offset `0x644b5c0`), an `R_X86_64_RELATIVE` relocation points to `0x43d00b` in `.rodata`. The next 16 bytes, `18000000000000001c00000025000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 28 and 37. The string's normalized suffix matches `l1/abci/abci_hash.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2bb3891` is `0x2bb3897` and the fallthrough is `0x2bb3893`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bb3889` | `660f2e0d7f578afd` | `ucomisd xmm1, qword ptr [rip - 0x275a881]` |
| `0x2bb3891` | `7404` | `je 0x2bb3897` |

## Argument flow


The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 59955044 added to `0x2bb38ac` gives the relocation slot `0x64e1010`. Its symbol-zero RELATIVE addend is `0x1547530`. The target's FDE at `0x104fe54` describes `[0x1547530, 0x1548ba3)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bb38a6` | `ff1564d79203` | `call qword ptr [rip + 0x392d764]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*644d5c0 '

readelf -rW "$target" | grep -i '0*64e1010 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2bb37c0 --stop-address=0x2bb38ac "$target"

od -An -tx1 -j 105166280 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43d00b --stop-address=0x43d023 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15239d8903`), re-decoding lands at `0x644d5c1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 28, column 37. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

