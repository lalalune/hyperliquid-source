# RE-001: map node #115 l1/agent_tracker.rs:137 conditional call edge


- Component allocation: `l1-shared`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/agent_tracker.rs` as an embedded path. At ELF VA `0x3be7e36` (file offset `0x3be6e36`), `488d15a3e68802` decodes as `lea rdx, [rip + 0x288e6a3]`. Adding the signed displacement `42526371` to the next instruction VA `0x3be7e3d` yields `0x64764e0`. The decode from the start of FDE range `[0x3be79a0, 0x3be7e79)` reaches that instruction boundary. The FDE itself is at `0x1241fb8`.


At `0x64764e0` (file offset `0x64744e0`), an `R_X86_64_RELATIVE` relocation points to `0x43e2a5` in `.rodata`. The next 16 bytes, `17000000000000008900000030000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 137 and 48. The string's normalized suffix matches `l1/agent_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x3be7bae` is `0x3be7e36` and the fallthrough is `0x3be7bb4`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jo` predicate (`OF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3be7bab` | `48f7d8` | `neg rax` |
| `0x3be7bae` | `0f8082020000` | `jo 0x3be7e36` |

## Argument flow


The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 42956946 added to `0x3be7e46` gives the relocation slot `0x64df6d8`. Its symbol-zero RELATIVE addend is `0x141e31e`. The target's FDE at `0xca7278` describes `[0x141e31e, 0x141e35b)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3be7e40` | `ff1592788f02` | `call qword ptr [rip + 0x28f7892]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64764e0 '

readelf -rW "$target" | grep -i '0*64df6d8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x3be79a0 --stop-address=0x3be7e46 "$target"

od -An -tx1 -j 105333992 -N 16 "$target"

objdump -s -j .rodata --start-address=0x43e2a5 --stop-address=0x43e2bc "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15a4e68802`), re-decoding lands at `0x64764e1`, which fails the exact descriptor-address check.


Overlap note: merged RE-001-node115-agent-first-match-erase pins this lea site as a source-location xref, the descriptor 0x64764e0 (agent_tracker.rs:137:48), and the call pc 0x3be7e40 with slot 0x64df6d8 as flat census entries, but pins neither the jo guard at 0x3be7bae, the guard-to-site edge, the rdx argument flow, nor the callee 0x141e31e — the edge itself is new ground (same census-row precedent as #4872/#4879).

## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 137, column 48. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

