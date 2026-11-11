# RE-001: map node #115 base/file_mod_time_tracker.rs:119 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/file_mod_time_tracker.rs` as an embedded path. At ELF VA `0x16e5974` (file offset `0x16e4974`), `488d0dfd5ad204` decodes as `lea rcx, [rip + 0x4d25afd]`. Adding the signed displacement `80894717` to the next instruction VA `0x16e597b` yields `0x640b478`. The decode from the start of FDE range `[0x16e5710, 0x16e5b93)` reaches that instruction boundary. The FDE itself is at `0x1074ec0`.

At `0x640b478` (file offset `0x6409478`), an `R_X86_64_RELATIVE` relocation points to `0x4345eb` in `.rodata`. The next 16 bytes, `21000000000000007700000011000000`, decode as a little-endian 64-bit length of 33 and two 32-bit values, 119 and 17. The string's normalized suffix matches `base/file_mod_time_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x16e58b4` is `0x16e590f` and the fallthrough is `0x16e58b6`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test r13, r13`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x16e58b1` | `4d85ed` | `test r13, r13` |
| `0x16e58b4` | `7459` | `je 0x16e590f` |
| `0x16e590f` | `48896c2458` | `mov qword ptr [rsp + 0x58], rbp` |
| `0x16e5914` | `48c744242000000000` | `mov qword ptr [rsp + 0x20], 0` |
| `0x16e591d` | `c744243000000000` | `mov dword ptr [rsp + 0x30], 0` |
| `0x16e5925` | `66c74424340000` | `mov word ptr [rsp + 0x34], 0` |
| `0x16e592c` | `488d442458` | `lea rax, [rsp + 0x58]` |
| `0x16e5931` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x16e5936` | `488b05eba2df04` | `mov rax, qword ptr [rip + 0x4dfa2eb]` |
| `0x16e593d` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x16e5942` | `488d05b882d5fe` | `lea rax, [rip - 0x12a7d48]` |
| `0x16e5949` | `4889442470` | `mov qword ptr [rsp + 0x70], rax` |
| `0x16e594e` | `488d442448` | `lea rax, [rsp + 0x48]` |
| `0x16e5953` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x16e5958` | `488d442470` | `lea rax, [rsp + 0x70]` |
| `0x16e595d` | `48890424` | `mov qword ptr [rsp], rax` |
| `0x16e5961` | `488d0528e8ffff` | `lea rax, [rip - 0x17d8]` |
| `0x16e5968` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x16e596d` | `488d35e35ed5fe` | `lea rsi, [rip - 0x12aa11d]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 81768847 added to `0x16e5989` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x16e597b` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x16e5980` | `4889e2` | `mov rdx, rsp` |
| `0x16e5983` | `ff158fb1df04` | `call qword ptr [rip + 0x4dfb18f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*640b478 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x16e5710 --stop-address=0x16e5989 "$target"
od -An -tx1 -j 104895616 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4345eb --stop-address=0x43460c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dfe5ad204`), re-decoding lands at `0x640b479`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
