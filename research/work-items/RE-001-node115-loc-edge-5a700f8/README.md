# RE-001: map node #115 node/node.rs:367 conditional call edge


- Component allocation: `node-runtime`.

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.

- Scope: one conditional call edge and its source-location record.


## Observation


The component catalogue lists `node/node.rs` as an embedded path. At ELF VA `0x5a700f8` (file offset `0x5a6f0f8`), `4c8d0dc98aa400` decodes as `lea r9, [rip + 0xa48ac9]`. Adding the signed displacement `10783433` to the next instruction VA `0x5a700ff` yields `0x64b8bc8`. The decode from the start of FDE range `[0x5a6e1e0, 0x5a70656)` reaches that instruction boundary. The FDE itself is at `0x13aa128`.


At `0x64b8bc8` (file offset `0x64b6bc8`), an `R_X86_64_RELATIVE` relocation points to `0x44aca3` in `.rodata`. The next 16 bytes, `10000000000000006f01000019000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 367 and 25. The string's normalized suffix matches `node/node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.


## Conditional edge


The taken target at branch `0x5a6e3ea` is `0x5a700f8` and the fallthrough is `0x5a6e3f0`. The **taken** edge reaches the location load along the instructions below.


The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a6e3e2` | `483b842468010000` | `cmp rax, qword ptr [rsp + 0x168]` |
| `0x5a6e3ea` | `0f85081d0000` | `jne 0x5a700f8` |

## Argument flow


The LEA writes `r9`. The trace follows the unchanged value to the call. At the call, `r9` is SysV x86-64 integer argument register 6. The signed displacement 10977215 added to `0x5a70119` gives the relocation slot `0x64e80d8`. Its symbol-zero RELATIVE addend is `0x5a5d384`. The target's FDE at `0xfc49c8` describes `[0x5a5d384, 0x5a5d3b7)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a70113` | `ff15bf7fa700` | `call qword ptr [rip + 0xa77fbf]` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*64b8bc8 '

readelf -rW "$target" | grep -i '0*64e80d8 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x5a6e1e0 --stop-address=0x5a70119 "$target"

od -An -tx1 -j 105606096 -N 16 "$target"

objdump -s -j .rodata --start-address=0x44aca3 --stop-address=0x44acb3 "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0dca8aa400`), re-decoding lands at `0x64b8bc9`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 367, column 25. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Overlap note: merged `RE-017-abci-expanded-result-115` pins this same guard (`jne` at `0x5a6e3ea` → `0x5a700f8`, transfers.tsv), the 35-byte `worker_bad_identity` window starting at the site `0x5a700f8` (windows.tsv, covering the lea, trace, and call bytes verbatim), and the call `0x5a70113` with slot `0x64e80d8` (transfers.tsv, unwind-links.tsv) — but it pins neither the descriptor `0x64b8bc8` nor the `node/src/node.rs:367:25` location, and names the site only as "the diagnostic". This packet supplies that location binding; the edge's guard/site/call bytes themselves are already on record there.

