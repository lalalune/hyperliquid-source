# RE-001: map node #115 l1/qtys/mod.rs:834 conditional call edge


- Component allocation: `assets`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `l1/qtys/mod.rs` as an embedded path. At ELF VA `0x2c012c7` (file offset `0x2c002c7`), `488d35f2a68803` decodes as `lea rsi, [rip + 0x388a6f2]`. Adding the signed displacement `59287282` to the next instruction VA `0x2c012ce` yields `0x648b9c0`. The decode from the start of FDE range `[0x2c00e90, 0x2c01378)` reaches that instruction boundary. The FDE itself is at `0x1188ea0`.


At `0x648b9c0` (file offset `0x64899c0`), an `R_X86_64_RELATIVE` relocation points to `0x435910` in `.rodata`. The next 16 bytes, `12000000000000004203000001000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 834 and 1. The string's normalized suffix matches `l1/qtys/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x2c011f4` is `0x2c012c7` and the fallthrough is `0x2c011fa`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jo` predicate (`OF = 1`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c011f1` | `4901ee` | `add r14, rbp` |
| `0x2c011f4` | `0f80cd000000` | `jo 0x2c012c7` |

## Argument flow


The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 59653074 added to `0x2c012d6` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c012d0` | `ff15d23b8e03` | `call qword ptr [rip + 0x38e3bd2]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*648b9c0 '

readelf -rW "$target" | grep -i '0*64e4ea8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x2c00e90 --stop-address=0x2c012d6 "$target"

od -An -tx1 -j 105421256 -N 16 "$target"

objdump -s -j .rodata --start-address=0x435910 --stop-address=0x435922 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35f3a68803`), re-decoding lands at `0x648b9c1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 834, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.


## Overlap note

Descriptor `0x648b9c0` is a shared panic-location literal: merged RE-001-node115-begin-block-monotonic-reset-bucket cites it as a Location record loaded at a different site (`0x2be509d`, `lea rsi, [rip + 0x38a691c]`). That packet pins neither the lea site `0x2c012c7`, the `jo` guard at `0x2c011f4`, nor the indirect call at `0x2c012d0` — the edge itself is new ground.
