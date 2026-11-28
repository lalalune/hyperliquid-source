# RE-008 Node #115 VecWriter signature recovery-byte view

The consensus bincode byte-match packet leaves the indirect byte load at
`0x59682c7` unresolved. This packet traces the view into that load from two
separate callers and compares safe Rust layouts to the target.

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF VAs in `.text`. DWARF FDEs bound the three inspected functions.
- Base: `cfeaee133b33ce9450a7434af19515b82171a8c6`.
- Prior evidence: [consensus byte matches](../RE-008-node115-consensus-bincode-encode-byte-matches/README.md)
  and [certificate caller wire order](../RE-008-node115-block-certificate-caller/README.md).
  The latter establishes eight varints followed by one recovery byte. The new
  result is how the VecWriter caller builds the temporary view for that byte.

## Observations

| Direct caller | 64-byte copy from aggregate | Pointer saved in view at `+0x40` | View passed in `rsi` |
| --- | --- | --- | --- |
| `0x4fb6659` | `r12 + 0x140..0x180` | `r12 + 0x180` stored at `rsp + 0x60` | `rsp + 0x20` |
| `0x5829265` | `rsi + 0x130..0x170` before call setup | original `rsi + 0x170` stored at `rsp + 0x40` | `rsp` |

In the first caller, `r12` comes from one load at the caller's input
pointer. The second reads its input directly. Each copies four 16-byte lanes
and takes an address of the immediately following byte in the same aggregate.
The callee at `0x59681d0` loads that address at `0x59682c7`, dereferences
one byte at `0x59682cc`, and writes it after the length/capacity check. On
success, both callers proceed to the writer at `0x5967060`.

A `#[repr(C)]` Rust view of two four-limb arrays and `&u8` reproduces the
exact seven-byte load sequence at relative offset `+0xf7`. Within the first
255 bytes, 215 of 223 non-relocation bytes match and eight guard-branch
displacements differ. The only omitted comparison bytes are the four-byte
ELF `PLT32` operands of eight calls whose target VAs independently decode
to `0x5822910`. The inline-`u8` control fails at the recovery load and
matches 207 of 223 non-relocation bytes over the same extent.

## Inference and limits

A borrowed recovery byte models the observed temporary view. The different
source offsets do not imply any change to the on-wire byte or order. Neither
caller window names the original aggregate type. The borrowed Rust candidate
is 333 bytes against the 354-byte FDE, so byte equivalence is open. The
capacity-growth path in the target calls `0x5963a10`, while the candidate
uses the compiler's current `Vec::push` lowering. The varint writer is an
ABI stand-in from the pinned sibling packet. This exercise does not provide
an executable encoder or runtime replay evidence, and it adds no full FDE
or component completion credit.

## Reproduce offline

From the repository root, with LLVM objdump/dwarfdump and Rust 1.95.0 plus
the `x86_64-unknown-linux-gnu` standard library installed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-signature-vecwriter-recovery/verify.py
(cd research/work-items/RE-008-node115-signature-vecwriter-recovery && sha256sum -c MANIFEST.sha256)
```

[Raw offline output](offline-log.txt) shows the artifact digest, FDE rows,
instruction windows, absolute call targets, exact compiler options and both
layout results. The candidate and target are never executed.
