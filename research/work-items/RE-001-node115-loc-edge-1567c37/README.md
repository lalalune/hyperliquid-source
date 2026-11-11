# RE-001: map node #115 base/fodname.rs:29 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/fodname.rs` as an embedded path. At ELF VA `0x1567c37` (file offset `0x1566c37`), `488d0d826ae904` decodes as `lea rcx, [rip + 0x4e96a82]`. Adding the signed displacement `82406018` to the next instruction VA `0x1567c3e` yields `0x63fe6c0`. The decode from the start of FDE range `[0x1567c10, 0x1568217)` reaches that instruction boundary. The FDE itself is at `0x10517ec`.

At `0x63fe6c0` (file offset `0x63fc6c0`), an `R_X86_64_RELATIVE` relocation points to `0x4377aa` in `.rodata`. The next 16 bytes, `13000000000000001d00000023000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 29 and 35. The string's normalized suffix matches `base/fodname.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1567c24` is `0x1567eae` and the fallthrough is `0x1567c2a`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp dword ptr [rsi], 1`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1567c21` | `833e01` | `cmp dword ptr [rsi], 1` |
| `0x1567c24` | `0f8584020000` | `jne 0x1567eae` |
| `0x1567c2a` | `48897c2410` | `mov qword ptr [rsp + 0x10], rdi` |
| `0x1567c2f` | `4c8b7610` | `mov r14, qword ptr [rsi + 0x10]` |
| `0x1567c33` | `488b5618` | `mov rdx, qword ptr [rsi + 0x18]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 83332471 added to `0x1567c51` gives the relocation slot `0x64e09c8`. Its symbol-zero RELATIVE addend is `0x1501f40`. The target's FDE at `0x104b030` describes `[0x1501f40, 0x15020f0)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1567c3e` | `488d7c2478` | `lea rdi, [rsp + 0x78]` |
| `0x1567c43` | `4c89f6` | `mov rsi, r14` |
| `0x1567c46` | `4889542408` | `mov qword ptr [rsp + 8], rdx` |
| `0x1567c4b` | `ff15778df704` | `call qword ptr [rip + 0x4f78d77]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe6c0 '
readelf -rW "$target" | grep -i '0*64e09c8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1567c10 --stop-address=0x1567c51 "$target"
od -An -tx1 -j 104842952 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4377aa --stop-address=0x4377bd "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d836ae904`), re-decoding lands at `0x63fe6c1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 29, column 35. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
