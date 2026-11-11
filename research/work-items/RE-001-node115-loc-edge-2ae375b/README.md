# RE-001: map node #115 node/evm_kvs.rs:95 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/evm_kvs.rs` as an embedded path. At ELF VA `0x2ae375b` (file offset `0x2ae275b`), `488d0dd6449603` decodes as `lea rcx, [rip + 0x39644d6]`. Adding the signed displacement `60179670` to the next instruction VA `0x2ae3762` yields `0x6447c38`. The decode from the start of FDE range `[0x2ae27c0, 0x2ae3cbf)` reaches that instruction boundary. The FDE itself is at `0x117c3f4`.

At `0x6447c38` (file offset `0x6445c38`), an `R_X86_64_RELATIVE` relocation points to `0x4432b3` in `.rodata`. The next 16 bytes, `13000000000000005f00000009000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 95 and 9. The string's normalized suffix matches `node/evm_kvs.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2ae36e6` is `0x2ae3775` and the fallthrough is `0x2ae36ec`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rax, 0x2e90edc`. The recorded edge is selected when the `jbe` predicate (`CF = 1 or ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ae36e0` | `483ddc0ee902` | `cmp rax, 0x2e90edc` |
| `0x2ae36e6` | `0f8689000000` | `jbe 0x2ae3775` |
| `0x2ae36ec` | `48c78424e000000000000000` | `mov qword ptr [rsp + 0xe0], 0` |
| `0x2ae36f8` | `c78424f000000000000000` | `mov dword ptr [rsp + 0xf0], 0` |
| `0x2ae3703` | `66c78424f40000000000` | `mov word ptr [rsp + 0xf4], 0` |
| `0x2ae370d` | `488d05e124b2fd` | `lea rax, [rip - 0x24ddb1f]` |
| `0x2ae3714` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x2ae3719` | `48c74424183b000000` | `mov qword ptr [rsp + 0x18], 0x3b` |
| `0x2ae3722` | `4c89ac2460010000` | `mov qword ptr [rsp + 0x160], r13` |
| `0x2ae372a` | `4c89642450` | `mov qword ptr [rsp + 0x50], r12` |
| `0x2ae372f` | `488d05daceb1ff` | `lea rax, [rip - 0x4e3126]` |
| `0x2ae3736` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x2ae373b` | `488d842460010000` | `lea rax, [rsp + 0x160]` |
| `0x2ae3743` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x2ae3748` | `488d0541c9b1ff` | `lea rax, [rip - 0x4e36bf]` |
| `0x2ae374f` | `4889442468` | `mov qword ptr [rsp + 0x68], rax` |
| `0x2ae3754` | `488d35ebe294fd` | `lea rsi, [rip - 0x26b1d15]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 60806051 added to `0x2ae3775` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ae3762` | `488dbc24e0000000` | `lea rdi, [rsp + 0xe0]` |
| `0x2ae376a` | `488d542450` | `lea rdx, [rsp + 0x50]` |
| `0x2ae376f` | `ff15a3d39f03` | `call qword ptr [rip + 0x39fd3a3]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6447c38 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2ae27c0 --stop-address=0x2ae3775 "$target"
od -An -tx1 -j 105143360 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4432b3 --stop-address=0x4432c6 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dd7449603`), re-decoding lands at `0x6447c39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 95, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
