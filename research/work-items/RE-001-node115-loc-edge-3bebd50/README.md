# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:433 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x3bebd50` (file offset `0x3bead50`), `488d1501a88802` decodes as `lea rdx, [rip + 0x288a801]`. Adding the signed displacement `42510337` to the next instruction VA `0x3bebd57` yields `0x6476558`. The decode from the start of FDE range `[0x3beb980, 0x3bebd62)` reaches that instruction boundary. The FDE itself is at `0xe4ef68`.

At `0x6476558` (file offset `0x6474558`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `2500000000000000b101000012000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 433 and 18. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x3bebb76` is `0x3bebd33` and the fallthrough is `0x3bebb7c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdi, qword ptr [rsp + 0x28]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3bebb71` | `483b7c2428` | `cmp rdi, qword ptr [rsp + 0x28]` |
| `0x3bebb76` | `0f83b7010000` | `jae 0x3bebd33` |
| `0x3bebd33` | `488b442420` | `mov rax, qword ptr [rsp + 0x20]` |
| `0x3bebd38` | `488b0c24` | `mov rcx, qword ptr [rsp]` |
| `0x3bebd3c` | `488908` | `mov qword ptr [rax], rcx` |
| `0x3bebd3f` | `48896808` | `mov qword ptr [rax + 8], rbp` |
| `0x3bebd43` | `4c897010` | `mov qword ptr [rax + 0x10], r14` |
| `0x3bebd47` | `488b4c2408` | `mov rcx, qword ptr [rsp + 8]` |
| `0x3bebd4c` | `48894818` | `mov qword ptr [rax + 0x18], rcx` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 42940606 added to `0x3bebd62` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x3bebd57` | `488b742428` | `mov rsi, qword ptr [rsp + 0x28]` |
| `0x3bebd5c` | `ff15be388f02` | `call qword ptr [rip + 0x28f38be]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6476558 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3beb980 --stop-address=0x3bebd62 "$target"
od -An -tx1 -j 105334112 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1502a88802`), re-decoding lands at `0x6476559`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 433, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
