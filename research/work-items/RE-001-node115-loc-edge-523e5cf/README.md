# RE-001: map node #115 l1/dex_registry/clearinghouses.rs:11 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/clearinghouses.rs` as an embedded path. At ELF VA `0x523e5cf` (file offset `0x523d5cf`), `4c8d05bad32401` decodes as `lea r8, [rip + 0x124d3ba]`. Adding the signed displacement `19190714` to the next instruction VA `0x523e5d6` yields `0x648b990`. The decode from the start of FDE range `[0x523d6b0, 0x523e70c)` reaches that instruction boundary. The FDE itself is at `0x1335384`.

At `0x648b990` (file offset `0x6489990`), an `R_X86_64_RELATIVE` relocation points to `0x434c18` in `.rodata`. The next 16 bytes, `25000000000000000b0000001d000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 11 and 29. The string's normalized suffix matches `l1/dex_registry/clearinghouses.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x523e141` is `0x523e5ba` and the fallthrough is `0x523e147`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r13, qword ptr [rax + 0x1340]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x523e13a` | `4c3ba840130000` | `cmp r13, qword ptr [rax + 0x1340]` |
| `0x523e141` | `0f8373040000` | `jae 0x523e5ba` |
| `0x523e5ba` | `66c74424205601` | `mov word ptr [rsp + 0x20], 0x156` |
| `0x523e5c1` | `488d3d4a4c59fb` | `lea rdi, [rip - 0x4a6b3b6]` |
| `0x523e5c8` | `488d0d29e02401` | `lea rcx, [rip + 0x124e029]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 19534010 added to `0x523e5e6` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x523e5d6` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x523e5db` | `be2b000000` | `mov esi, 0x2b` |
| `0x523e5e0` | `ff15ba102a01` | `call qword ptr [rip + 0x12a10ba]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b990 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x523d6b0 --stop-address=0x523e5e6 "$target"
od -An -tx1 -j 105421208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x434c18 --stop-address=0x434c3d "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05bbd32401`), re-decoding lands at `0x648b991`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 11, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
