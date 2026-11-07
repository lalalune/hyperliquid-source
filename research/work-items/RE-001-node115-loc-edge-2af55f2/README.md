# RE-001: map node #115 node/nv_stream.rs:143 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/nv_stream.rs` as an embedded path. At ELF VA `0x2af55f2` (file offset `0x2af45f2`), `4c8d05772d9503` decodes as `lea r8, [rip + 0x3952d77]`. Adding the signed displacement `60108151` to the next instruction VA `0x2af55f9` yields `0x6448370`. The decode from the start of FDE range `[0x2af45f0, 0x2af652a)` reaches that instruction boundary. The FDE itself is at `0x117c9dc`.

At `0x6448370` (file offset `0x6446370`), an `R_X86_64_RELATIVE` relocation points to `0x43bce4` in `.rodata`. The next 16 bytes, `15000000000000008f00000016000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 143 and 22. The string's normalized suffix matches `node/nv_stream.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2af55c6` establish a local edge into the argument setup. The taken target is `0x2af5d3c` and the fallthrough is `0x2af55cc`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test rax, rax`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af55c3` | `4885c0` | `test rax, rax` |
| `0x2af55c6` | `0f8470070000` | `je 0x2af5d3c` |
| `0x2af55cc` | `48c70001000000` | `mov qword ptr [rax], 1` |
| `0x2af55d3` | `48c7400801000000` | `mov qword ptr [rax + 8], 1` |
| `0x2af55db` | `4c896010` | `mov qword ptr [rax + 0x10], r12` |
| `0x2af55df` | `4c896818` | `mov qword ptr [rax + 0x18], r13` |
| `0x2af55e3` | `4c896020` | `mov qword ptr [rax + 0x20], r12` |
| `0x2af55e7` | `4c897028` | `mov qword ptr [rax + 0x28], r14` |
| `0x2af55eb` | `488d15850cb1fd` | `lea rdx, [rip - 0x24ef37b]` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -6237838 added to `0x2af560e` gives `0x2502780`. The target's FDE at `0x111cde4` describes `[0x2502780, 0x2502b4c)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2af55f9` | `488dbc2440060000` | `lea rdi, [rsp + 0x640]` |
| `0x2af5601` | `b912000000` | `mov ecx, 0x12` |
| `0x2af5606` | `4889c6` | `mov rsi, rax` |
| `0x2af5609` | `e872d1a0ff` | `call 0x2502780` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6448370 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2af45f0 --stop-address=0x2af560e "$target"
od -An -tx1 -j 105145208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43bce4 --stop-address=0x43bcf9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05782d9503`), re-decoding lands at `0x6448371`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 143, column 22. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
