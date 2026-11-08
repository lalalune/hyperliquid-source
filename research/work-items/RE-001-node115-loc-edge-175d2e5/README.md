# RE-001: map node #115 base/file_mod_time_tracker.rs:62 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x175d2e5` (file offset `0x175c2e5`), `488d0da4e1ca04` decodes as `lea rcx, [rip + 0x4cae1a4]`. Adding the signed displacement `80404900` to the next instruction VA `0x175d2ec` yields `0x640b490`. The decode from the start of FDE range `[0x175d250, 0x175d4f2)` reaches that instruction boundary. The FDE itself is at `0x107ff5c`.

At `0x640b490` (file offset `0x6409490`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000003e0000000d000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 62 and 13. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x175d27c` is `0x175d2fc` and the fallthrough is `0x175d27e`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rbx + 0x50], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x175d277` | `48837b5000` | `cmp qword ptr [rbx + 0x50], 0` |
| `0x175d27c` | `747e` | `je 0x175d2fc` |
| `0x175d27e` | `488d4350` | `lea rax, [rbx + 0x50]` |
| `0x175d282` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x175d286` | `48c744243800000000` | `mov qword ptr [rsp + 0x38], 0` |
| `0x175d28f` | `c744244800000000` | `mov dword ptr [rsp + 0x48], 0` |
| `0x175d297` | `66c744244c0000` | `mov word ptr [rsp + 0x4c], 0` |
| `0x175d29e` | `4889e0` | `mov rax, rsp` |
| `0x175d2a1` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x175d2a6` | `488d05b3e4f6ff` | `lea rax, [rip - 0x91b4d]` |
| `0x175d2ad` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x175d2b2` | `488d05ae69cefe` | `lea rax, [rip - 0x1319652]` |
| `0x175d2b9` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x175d2be` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x175d2c3` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x175d2c8` | `488d442408` | `lea rax, [rsp + 8]` |
| `0x175d2cd` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x175d2d2` | `488d05b76ef8ff` | `lea rax, [rip - 0x79149]` |
| `0x175d2d9` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x175d2de` | `488d3572e5cdfe` | `lea rsi, [rip - 0x1321a8e]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 81279004 added to `0x175d2fc` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x175d2ec` | `488d7c2438` | `lea rdi, [rsp + 0x38]` |
| `0x175d2f1` | `488d542428` | `lea rdx, [rsp + 0x28]` |
| `0x175d2f6` | `ff151c38d804` | `call qword ptr [rip + 0x4d8381c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*640b490 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x175d250 --stop-address=0x175d2fc "$target"
od -An -tx1 -j 104895640 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0da5e1ca04`), re-decoding lands at `0x640b491`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 62, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
