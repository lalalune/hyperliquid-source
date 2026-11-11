# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x452ae56` (file offset `0x4529e56`), `488d158b44f601` decodes as `lea rdx, [rip + 0x1f6448b]`. Adding the signed displacement `32916619` to the next instruction VA `0x452ae5d` yields `0x648f2e8`. The decode from the start of FDE range `[0x452aab0, 0x452aeb9)` reaches that instruction boundary. The FDE itself is at `0x12aa918`.

At `0x648f2e8` (file offset `0x648d2e8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x452ac1f` is `0x452ae25` and the fallthrough is `0x452ac25`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test eax, eax`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x452ac1d` | `85c0` | `test eax, eax` |
| `0x452ac1f` | `0f8400020000` | `je 0x452ae25` |
| `0x452ae25` | `488d05c38f2afc` | `lea rax, [rip - 0x3d5703d]` |
| `0x452ae2c` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x452ae31` | `48c744242841000000` | `mov qword ptr [rsp + 0x28], 0x41` |
| `0x452ae3a` | `488d442420` | `lea rax, [rsp + 0x20]` |
| `0x452ae3f` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x452ae43` | `488d05a6291b00` | `lea rax, [rip + 0x1b29a6]` |
| `0x452ae4a` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x452ae4f` | `488d3d010af1fb` | `lea rdi, [rip - 0x40ef5ff]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 33245266 added to `0x452ae66` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x452ae5d` | `4889e6` | `mov rsi, rsp` |
| `0x452ae60` | `ff155248fb01` | `call qword ptr [rip + 0x1fb4852]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648f2e8 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x452aab0 --stop-address=0x452ae66 "$target"
od -An -tx1 -j 105435888 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d158c44f601`), re-decoding lands at `0x648f2e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
