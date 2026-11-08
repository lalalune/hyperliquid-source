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

**Correction (2026-11-08):** the first submission claimed the descriptor reaches the indirect call at `0x1563508` as argument 4. That claim is withdrawn — slopbot's review was right. Between the location load and that call, `rcx` is overwritten at `0x15634f4` by `lea rcx, [rip + 0x4e9b015]` (`488d0d15b0e904`), which reaches descriptor `0x63fe510` — a RELATIVE relocation to the same string `base/src/u.rs`, raw fields length 13 / line 518 / column 17. So the call at `0x1563508` takes the **:518** descriptor as argument 4, not the :512 descriptor.

The correct consumer is the direct call immediately after the location load. The LEA writes `rcx`; `rdi`/`rsi`/`rdx` are set up at `0x1563440`/`0x1563448`/`0x1563450`, and `rcx` still holds the :512 descriptor when the call executes. At the call, `rcx` is SysV x86-64 integer argument register 4. The call is a direct `E8` with rel32 `-390669` (`e8f308faff`), target `0x1503d50`. The target's FDE at `0x104b394` describes `[0x1503d50, 0x15040ae)`.


| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1563440` | `488dbc24b0010000` | `lea rdi, [rsp + 0x1b0]` |
| `0x1563448` | `488bb42488000000` | `mov rsi, qword ptr [rsp + 0x88]` |
| `0x1563450` | `488b942410010000` | `mov rdx, qword ptr [rsp + 0x110]` |
| `0x1563458` | `e8f308faff` | `call 0x1503d50` |


## Reproduce


Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.


```sh
target=artifacts/node/115/hl-node

printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -

readelf -rW "$target" | grep -i '0*63fe4e0 '

readelf -rW "$target" | grep -i '0*63fe510 '

readelf --debug-dump=frames "$target"

objdump -d -M intel --start-address=0x1562670 --stop-address=0x156350e "$target"

od -An -tx1 -j 104842472 -N 16 "$target"

objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```


Local extraction used Python 3.12, Capstone 5.0.7 and pyelftools on this VM. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0da1b0e904`), re-decoding lands at `0x63fe4e1`, which fails the exact descriptor-address check.


## Interpretation and limits


The layout is consistent with Rust source-location metadata for line 512, column 15. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the descriptor through the callee `0x1503d50` to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.

Correction note: the original submission named the indirect call at `0x1563508` as the consumer; that was wrong (see Argument flow) and is corrected above. The edge and the descriptor decode are unchanged.

Overlap note: the guard instruction and the lea site also appear in the raw disassembly export of merged RE-014-host-ip-gates-115 (`owners.gnu.txt`), which pins a different edge in the same region (`base/u.rs:457`); the descriptor binding for line 512 is not recorded there.

