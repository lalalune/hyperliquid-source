# RE-001: map node #115 node/node.rs:251 conditional call edge


- Component allocation: `node-runtime`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `node/node.rs` as an embedded path. At ELF VA `0x2aee5f7` (file offset `0x2aed5f7`), `4c8d0d32959503` decodes as `lea r9, [rip + 0x3959532]`. Adding the signed displacement `60134706` to the next instruction VA `0x2aee5fe` yields `0x6447b30`. The decode from the start of FDE range `[0x2aeaef0, 0x2af0654)` reaches that instruction boundary. The FDE itself is at `0x117c598`.


At `0x6447b30` (file offset `0x6445b30`), an `R_X86_64_RELATIVE` relocation points to `0x44aca3` in `.rodata`. The next 16 bytes, `1000000000000000fb0000000d000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 251 and 13. The string's normalized suffix matches `node/node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2aebfd1` is `0x2aee5f7` and the fallthrough is `0x2aebfd7`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2aebfcc` | `0f9544244d` | `setne byte ptr [rsp + 0x4d]` |
| `0x2aebfd1` | `0f8420260000` | `je 0x2aee5f7` |

## Argument flow


The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 60764678 added to `0x2aee612` gives the relocation slot `0x64e1818`. Its symbol-zero RELATIVE addend is `0x15e0f2a`. The target's FDE at `0xcbb500` describes `[0x15e0f2a, 0x15e0f5d)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2aee60c` | `ff1506329f03` | `call qword ptr [rip + 0x39f3206]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*6447b30 '

readelf -rW "$target" | grep -i '0*64e1818 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2aeaef0 --stop-address=0x2aee612 "$target"

od -An -tx1 -j 105143096 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44aca3 --stop-address=0x44acb3 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d33959503`), re-decoding lands at `0x6447b31`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 251, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: merged `RE-015-restart-threshold-115` lists `0x2aee5f7` as an exception-table address in its `exceptions.tsv` `resume_poll` row, but pins neither the descriptor `0x6447b30`, the `node.rs:251` location, the `je` guard, nor the call at `0x2aee60c` — the edge itself is new ground.

