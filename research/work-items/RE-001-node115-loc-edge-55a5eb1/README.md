# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:17 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x55a5eb1` (file offset `0x55a4eb1`), `4c8d05f05aee00` decodes as `lea r8, [rip + 0xee5af0]`. Adding the signed displacement `15620848` to the next instruction VA `0x55a5eb8` yields `0x648b9a8`. The decode from the start of FDE range `[0x55a5d40, 0x55a5f08)` reaches that instruction boundary. The FDE itself is at `0x135bd20`.

At `0x648b9a8` (file offset `0x64899a8`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000001100000021000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 17 and 33. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x55a5dbb` is `0x55a5e9c` and the fallthrough is `0x55a5dc1`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, r15`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55a5db8` | `4d39fe` | `cmp r14, r15` |
| `0x55a5dbb` | `0f83db000000` | `jae 0x55a5e9c` |
| `0x55a5e9c` | `66c74424205601` | `mov word ptr [rsp + 0x20], 0x156` |
| `0x55a5ea3` | `488d3d68d322fb` | `lea rdi, [rip - 0x4dd2c98]` |
| `0x55a5eaa` | `488d0d4767ee00` | `lea rcx, [rip + 0xee6747]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 15964120 added to `0x55a5ec8` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x55a5eb8` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x55a5ebd` | `be2b000000` | `mov esi, 0x2b` |
| `0x55a5ec2` | `ff15d897f300` | `call qword ptr [rip + 0xf397d8]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b9a8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x55a5d40 --stop-address=0x55a5ec8 "$target"
od -An -tx1 -j 105421232 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05f15aee00`), re-decoding lands at `0x648b9a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 17, column 33. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
