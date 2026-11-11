# RE-001: map node #115 l1/clearinghouse/oracle/oracle.rs:433 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/oracle/oracle.rs` as an embedded path. At ELF VA `0x276def5` (file offset `0x276cef5`), `488d15ecd2cc03` decodes as `lea rdx, [rip + 0x3ccd2ec]`. Adding the signed displacement `63754988` to the next instruction VA `0x276defc` yields `0x643b1e8`. The decode from the start of FDE range `[0x276d4d0, 0x276dff9)` reaches that instruction boundary. The FDE itself is at `0x1137ae4`.

At `0x643b1e8` (file offset `0x64391e8`), an `R_X86_64_RELATIVE` relocation points to `0x448ed3` in `.rodata`. The next 16 bytes, `2500000000000000b101000012000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 433 and 18. The string's normalized suffix matches `l1/clearinghouse/oracle/oracle.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x276da8a` is `0x276dee8` and the fallthrough is `0x276da90`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdi, qword ptr [rsp + 0x20]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x276da85` | `483b7c2420` | `cmp rdi, qword ptr [rsp + 0x20]` |
| `0x276da8a` | `0f8358040000` | `jae 0x276dee8` |
| `0x276dee8` | `488b442410` | `mov rax, qword ptr [rsp + 0x10]` |
| `0x276deed` | `4889842490000000` | `mov qword ptr [rsp + 0x90], rax` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 64427801 added to `0x276df07` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x276defc` | `488b742420` | `mov rsi, qword ptr [rsp + 0x20]` |
| `0x276df01` | `ff151917d703` | `call qword ptr [rip + 0x3d71719]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*643b1e8 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x276d4d0 --stop-address=0x276df07 "$target"
od -An -tx1 -j 105091568 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448ed3 --stop-address=0x448ef8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15edd2cc03`), re-decoding lands at `0x643b1e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 433, column 18. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
