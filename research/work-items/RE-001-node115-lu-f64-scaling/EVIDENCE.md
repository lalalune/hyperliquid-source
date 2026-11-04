# RE-001: node #115 lu.rs f64-to-scaled-integer conversion

- Component ID: RE-001 (function map), `base/src/lu.rs` conversion.
- Target release and full SHA-256: node #115, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only migration). No inferred reference source is used as a correctness oracle.
- Claim status: observation for the dispatch tables, the exponent thresholds, the 10^9 scale and carry guard, the 112-byte output span, the tag writes, the five `lu.rs` sites, and the 4-member skeleton family; inference for the Duration-family reading of the 10^9 scale; unresolved for the staged `[rsp+0x90..0x100]` copy's role, the compare helper's semantics, and this instance's direct reachability.
- Scope included and excluded: included — one 955-byte conversion instance (`0x15d5cb0..0x15d606b`), its two 4-entry tables, its `lu.rs`/`time.rs` Location records, its 4-member skeleton family, and two contextual functions (`0x15d6e00`, `0x15d6ef0`). Excluded — Rust reimplementation, Duration-type proof, the compare/post-scale/worker internals, the other 41 same-size FDEs, any gate request, and any node #94 material (different binary, out of scope).

## Reproduce

Working directory: the repository root at upstream main `8fd8db6`. Platform: Linux x86-64. Tools: GNU objdump (binutils), Python 3.12, and the repository's own `tools/elf_index.py` / `tools/fde_extents.py` (no target execution; the node binary is never run).

- `sha256sum artifacts/node/115/hl-node` → `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes).
- `objdump -d -M intel --start-address=0x15d5cb0 --stop-address=0x15d606b artifacts/node/115/hl-node` → retained as `conversion.objdump.txt` (235 native instructions).
- `objdump -d -M intel --start-address=0x15d6e00 --stop-address=0x15d6ee1 artifacts/node/115/hl-node` → retained as `caller.objdump.txt` (60 native instructions).
- `python3 tools/node115_lu_f64_scaling.py` → verifies the digest, both bodies, both tables, all four Location records (via RELATIVE relocation addends), the FDE records, and the skeleton-family site pattern; prints the verified record.
- `python3 -m unittest tests.test_node115_lu_f64_scaling -v` → unit tests including corruption controls (digest mismatch, body corruption, table-entry corruption, record corruption, and caller-count change are all rejected).
- No execution, no network, no side effects beyond reading the target file.

## Evidence

Coordinate system: virtual addresses (VA) as linked; file offsets via the section map (`.text` VA `0x1419300` = file offset `0x1418300`, so offset = VA − `0x1000`; `.rodata` VA = file offset; `.data.rel.ro` VA `0x63f3c20` = file offset `0x63f1c20`, so offset = VA − `0x2000`; `.eh_frame` VA = file offset; `.rela.dyn` VA = file offset, 24-byte entries). All boundaries are FDE half-open ranges from the repository's own `.eh_frame` walk (135,313 FDEs, zero overlaps on the full walk).

- Conversion instance: `0x15d5cb0..0x15d606b` (955 bytes, file offset `0x15d4cb0`), FDE record at VA `0x105b070` (84 bytes), CIE at `0x103d604` (32 bytes), LSDA at `0x1823b0`, body SHA-256 `1f95e20d63dd2cf0a6633a332a819d502b16a81c7d98f782c202f9f3c7129013`.
- Caller context: `0x15d6e00..0x15d6ee1` (225 bytes, file offset `0x15d4e00`), FDE `0x105b298`, LSDA `0x182588`, body SHA-256 `f67421d347a9c24235ab5cde484e63496242931756f23f295e4792ac57bbf425`.
- Guard context: `0x15d6ef0..0x15d6fc4` (212 bytes, file offset `0x15d4ef0`), FDE `0x105b2cc`, LSDA `0x1825b8`, body SHA-256 `e2216cdf32fe765abbb91798b77e4c2a7395777b567114eca2190a3aae06b373`.
- Dispatch tables (`.rodata`): `0x4699e8` (file offset `0x4699e8`, 16 bytes, entries → `0x15d5cde`/`0x15d5fb4`/`0x15d5fa7`/`0x15d5cfd`) and `0x4699f8` (file offset `0x4699f8`, 16 bytes, entries → `0x15d5d1f`/`0x15d5fd0`/`0x15d5fc1`/`0x15d5f37`). Each table is used by exactly one `lea` site in the binary (`0x15d5cce`, `0x15d5d0f`), established by a whole-`.text` `lea` census (420,815 sites).
- Location records (`.data.rel.ro`, 24 bytes each: RELATIVE addend → path string, length, line|col<<32). The file bytes of the pointer slot are zero; the pointer resolves through the `.rela.dyn` RELATIVE addend, not the file qword. `0x6401288` → `base/src/lu.rs` 63:46 (addend `0x4326c1`, string at file offset `0x4326c1`, length 14). `0x64012d0` → 74:57. `0x64012b8` → 75:5. `0x6400e90` → `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/core/src/time.rs` 962:23 (addend `0x44f1ac`, length 72).
- Callers/callees: direct `E8` census over the whole `.text` (121,656 distinct targets). Conversion instance callers: `0x15d6e4c`, `0x15d5bc7` (2 total). Conversion callees: compare helper GOT `0x64e0858` → `0x5cf2d30` (703-byte FDE), post-scale helper GOT `0x64e13a0` → `0x5cf2150` (409-byte FDE), drop helpers GOT `0x64dfdc8` → `0x5ce8da0` (801-byte FDE) and GOT `0x64dfdb8` → `0x5ce86d0` (389-byte FDE), drop finisher `0x15df190` (136-byte FDE). Guard once helper GOT `0x64df9f0` → `0x5c87d50` (540-byte FDE). No `E8`, `E9`, qword, or `lea` reference to `0x15d6e00` or `0x15d5b00` was found in `.text`, `.rodata`, or `.data.rel.ro`.
- Skeleton family: linear disassembly from each FDE start gives identical 235-instruction mnemonic sequences for `0x15d5cb0`, `0x15ebbe0`, `0x2a90a50`, `0x2c7f360`, each with the same five `lu.rs` site pattern at corresponding positions and direct `E8` counts 2/3/10/7. The other 41 same-size FDEs fall into 23 other skeletons. Analysis was complete for the characterized instance and its family; the compare helper, post-scale helper, and shared worker were mapped as targets only, not decoded.

## Implementation and comparison

Independent Rust path: not yet implemented/measured. No Cargo project, no build, no normalized comparison is claimed for this packet. The verifier is a static checker only: it re-reads the target bytes, the tables, the relocation addends, and the FDE records, and rejects any change to them. Corruption controls cover the node digest, both pinned bodies, both table raw bytes, each Location record's addend/string/length/line/col, the FDE start/end records, and the family members' site patterns and call counts.

## Results and limitations

Verified counts (denominators explicit): 1 characterized FDE (955 bytes / 235 instructions); 2 dispatch tables × 4 entries (8/8 targets resolved inside the characterized function except the panic arms, which are inside it too — all 8 targets lie in `0x15d5cb0..0x15d606b`); 4 Location records (3 `lu.rs` + 1 `time.rs`); 4 skeleton-family members with 22 direct `E8` calls total (2+3+10+7); 2 contextual FDEs (225 + 212 bytes); 0 direct references to the two contextual callers' entry points. All checks pass in the accompanying tool and tests.

What remains unknown: the Rust type and variant names; whether the 10^9-scaled output is a Duration (inference only); what the compare helper compares (value vs identity); what the staged `[rsp+0x90..0x100]` copy is for; what the other 41 same-size FDEs do; and by what mechanism, if any, the two contextual callers are reached (no direct control-flow reference was found).

No progress gate is requested by this packet, and that is stated deliberately: the packet maps behavior but does not reconstruct a component behind a gate. Next question: decode the compare helper at `0x5cf2d30` (703 bytes) to decide whether tag 1 vs 3 means value-equality or identity, which determines what the caller state machine at `0x15d6e00` can rely on.
