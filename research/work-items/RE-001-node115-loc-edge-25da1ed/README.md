# RE-001: map node #115 l1/perp_meta.rs:287 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/perp_meta.rs` as an embedded path. At ELF VA `0x25da1ed` (file offset `0x25d91ed`), `488d3d64e0e903` decodes as `lea rdi, [rip + 0x3e9e064]`. Adding the signed displacement `65658980` to the next instruction VA `0x25da1f4` yields `0x6478258`. The decode from the start of FDE range `[0x25da0b0, 0x25da1fa)` reaches that instruction boundary. The FDE itself is at `0xd2b574`.

At `0x6478258` (file offset `0x6476258`), an `R_X86_64_RELATIVE` relocation points to `0x437df7` in `.rodata`. The next 16 bytes, `13000000000000001f0100001c000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 287 and 28. The string's normalized suffix matches `l1/perp_meta.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x25da112` is `0x25da1ed` and the fallthrough is `0x25da118`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 7`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x25da10f` | `83f807` | `cmp eax, 7` |
| `0x25da112` | `0f83d5000000` | `jae 0x25da1ed` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 66082382 added to `0x25da1fa` gives the relocation slot `0x64df848`. Its symbol-zero RELATIVE addend is `0x1681e40`. The target's FDE at `0xcc3320` describes `[0x1681e40, 0x1681e59)`.

## Callee identification

The resolved callee selects the diagnostic ``attempt to subtract with overflow``. Its bytes at `0x46eb80` are `617474656d707420746f2073756274726163742077697468206f766572666c6f77`. The wrapper's RIP-relative indirect call uses slot `0x64df6b8`, whose RELATIVE addend is the sink at `0x1680e80`. The wrapper trace and sink FDE are recorded alongside the source-location record.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x25da1f4` | `ff154e56f003` | `call qword ptr [rip + 0x3f0564e]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6478258 '
readelf -rW "$target" | grep -i '0*64df848 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x25da0b0 --stop-address=0x25da1fa "$target"
objdump -d -M intel --start-address=0x1681e40 --stop-address=0x1681e59 "$target"
objdump -s -j .rodata --start-address=0x46eb80 --stop-address=0x46eba1 "$target"
readelf -rW "$target" | grep -i '0*64df6b8 '
od -An -tx1 -j 105341536 -N 16 "$target"
objdump -s -j .rodata --start-address=0x437df7 --stop-address=0x437e0a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d65e0e903`), re-decoding lands at `0x6478259`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 287, column 28. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
