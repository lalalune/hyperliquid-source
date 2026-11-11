# RE-001: map node #115 node/consensus/state.rs:495 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/consensus/state.rs` as an embedded path. At ELF VA `0x2e12d53` (file offset `0x2e11d53`), `488d0d16ee6303` decodes as `lea rcx, [rip + 0x363ee16]`. Adding the signed displacement `56880662` to the next instruction VA `0x2e12d5a` yields `0x6451b70`. The decode from the start of FDE range `[0x2e11b00, 0x2e13c3a)` reaches that instruction boundary. The FDE itself is at `0x11b21b8`.

At `0x6451b70` (file offset `0x644fb70`), an `R_X86_64_RELATIVE` relocation points to `0x43e0ae` in `.rodata`. The next 16 bytes, `1b00000000000000ef0100000d000000`, decode as a little-endian 64-bit length of 27 and two 32-bit values, 495 and 13. The string's normalized suffix matches `node/consensus/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2e12c7f` is `0x2e12d6d` and the fallthrough is `0x2e12c85`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rsp + 0x270], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e12c76` | `4883bc247002000000` | `cmp qword ptr [rsp + 0x270], 0` |
| `0x2e12c7f` | `0f84e8000000` | `je 0x2e12d6d` |
| `0x2e12c85` | `48c744246000000000` | `mov qword ptr [rsp + 0x60], 0` |
| `0x2e12c8e` | `c744247000000000` | `mov dword ptr [rsp + 0x70], 0` |
| `0x2e12c96` | `66c74424740000` | `mov word ptr [rsp + 0x74], 0` |
| `0x2e12c9d` | `488d842458020000` | `lea rax, [rsp + 0x258]` |
| `0x2e12ca5` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x2e12caa` | `488d051f350200` | `lea rax, [rip + 0x2351f]` |
| `0x2e12cb1` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x2e12cb6` | `488d05f84280fd` | `lea rax, [rip - 0x27fbd08]` |
| `0x2e12cbd` | `48898424c0020000` | `mov qword ptr [rsp + 0x2c0], rax` |
| `0x2e12cc5` | `488d442410` | `lea rax, [rsp + 0x10]` |
| `0x2e12cca` | `48898424c8020000` | `mov qword ptr [rsp + 0x2c8], rax` |
| `0x2e12cd2` | `488b442440` | `mov rax, qword ptr [rsp + 0x40]` |
| `0x2e12cd7` | `48898424d8000000` | `mov qword ptr [rsp + 0xd8], rax` |
| `0x2e12cdf` | `488d842408020000` | `lea rax, [rsp + 0x208]` |
| `0x2e12ce7` | `4889842480020000` | `mov qword ptr [rsp + 0x280], rax` |
| `0x2e12cef` | `488d8424c0020000` | `lea rax, [rsp + 0x2c0]` |
| `0x2e12cf7` | `48898424f0000000` | `mov qword ptr [rsp + 0xf0], rax` |
| `0x2e12cff` | `488d050ad97eff` | `lea rax, [rip - 0x8126f6]` |
| `0x2e12d06` | `48898424f8000000` | `mov qword ptr [rsp + 0xf8], rax` |
| `0x2e12d0e` | `488d8424d8000000` | `lea rax, [rsp + 0xd8]` |
| `0x2e12d16` | `4889842400010000` | `mov qword ptr [rsp + 0x100], rax` |
| `0x2e12d1e` | `488d05ebd57eff` | `lea rax, [rip - 0x812a15]` |
| `0x2e12d25` | `4889842408010000` | `mov qword ptr [rsp + 0x108], rax` |
| `0x2e12d2d` | `488d842480020000` | `lea rax, [rsp + 0x280]` |
| `0x2e12d35` | `4889842410010000` | `mov qword ptr [rsp + 0x110], rax` |
| `0x2e12d3d` | `488d05ccd37eff` | `lea rax, [rip - 0x812c34]` |
| `0x2e12d44` | `4889842418010000` | `mov qword ptr [rsp + 0x118], rax` |
| `0x2e12d4c` | `488d35c3f662fd` | `lea rsi, [rip - 0x29d093d]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 57466283 added to `0x2e12d6d` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e12d5a` | `488d7c2460` | `lea rdi, [rsp + 0x60]` |
| `0x2e12d5f` | `488d9424f0000000` | `lea rdx, [rsp + 0xf0]` |
| `0x2e12d67` | `ff15abdd6c03` | `call qword ptr [rip + 0x36cddab]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6451b70 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2e11b00 --stop-address=0x2e12d6d "$target"
od -An -tx1 -j 105184120 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e0ae --stop-address=0x43e0c9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d17ee6303`), re-decoding lands at `0x6451b71`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 495, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
