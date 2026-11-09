# RE-001: node #115 FDE and control-transfer census, band 3d

- **Component allocation:** `foundation` in the generated component map; this is only a work allocation, not recovered ownership.
- **Target:** Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source commit:** `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- **Bounded question:** Re-derive every unwind-described range whose start is in `.text` VA interval `[0x3ac0000, 0x3b0000)`, confirm its complete target-byte coverage, and record statically decoded calls and jumps for RE-001's node #115 function-map evidence.
- **Claim status:** FDE and byte observations; transfer destinations are disassembler-derived static observations. Names, logical function boundaries and behavior remain unknown.

The interval continues the neighboring-band census: merged PR [#2940](https://github.com/lalalune/hyperliquid-source/pull/2940) covers `[0x3a00000, 0x3a40000)`, open PR [#5064](https://github.com/lalalune/hyperliquid-source/pull/5064) covers `[0x3a40000, 0x3a80000)`, and open PR [#5412](https://github.com/lalalune/hyperliquid-source/pull/5412) covers `[0x3a80000, 0x3ac0000)`. The live search at selection time found no PR for the new half-open interval; the exact queries and adjacent match are recorded in `selection.json`.

## Reproduce

From the repository root, with the pinned node #115 artifact present and Python 3:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-001-node115-fde-band3d-census/verify.py --write
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-001-node115-fde-band3d-census/verify.py
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-001-node115-fde-band3d-census/verify.py --self-test
```

`--write` derives the saved records from the pinned binary using `tools/elf_index.py`, `tools/fde_extents.py`, and the recorded static disassembler. The verifier checks the ELF identity, unwind-header membership, full `.eh_frame` records, all selected body bytes and hashes, disassembly coverage, control-transfer rows, and the packet manifest. `--self-test` first verifies the packet and then rejects a modified evidence hash even after the packet manifest is recomputed.

## Evidence

The `.text` section is VA `0x1419300`, file offset `0x1418300`, size `0x4fd7700`. A VA maps to file offset by `section_offset + VA - section_address`. FDE records come from `.eh_frame`; every selected `(start, FDE record)` also occurs in `.eh_frame_hdr`.

- 66 unique, ordered, disjoint FDE extents start in the selected band.
- All 262,682 bytes across those extents decode contiguously. `evidence.json` stores body hashes, instruction counts, and FDE/CIE record hashes; `frames.txt` preserves the raw FDE record bytes.
- The records contain 52,719 instruction rows and 10,866 call/jump references: 9,592 direct destinations, 1,146 visible RIP-relative indirect slots, and 128 register-indirect or unresolved operands. `edges.tsv` keeps each source FDE, instruction address, mnemonic, operand, and any visible destination or slot. Only direct code destinations are marked for whether their VA falls inside the selected band; that flag does not assert a function start.
- The smallest extent is `0x3accd80..0x3acd40b` (1,675 bytes, 368 decoded instruction rows).
- The final selected start is `0x3aff1a0`; its unwind extent ends at `0x3b00597`, beyond the band boundary but inside `.text`. Selection is by FDE start, so the full extent is retained.

Tool identity: Apple LLVM `llvm-objdump` 21.0.0 and Python 3.14.3 on macOS arm64. The target was authenticated by its pinned SHA-256 and detached project signature, read as data, and never executed or copied. The repository public key was imported into a temporary isolated GPG home for signature verification.

## Limits and next step

An FDE is an unwind range, not proof of a logical function boundary. The census does not establish source names, callers outside this band, component ownership, data types, complete CFGs, runtime branch selection, or semantics. `edges.tsv` records `call` and `j*` instructions only; it omits returns and fallthrough, and leaves indirect targets unresolved. Direct destinations are those printed by the recorded disassembler; no loader relocation is applied. No implementation, binary comparison, component gate, or whole-module denominator is claimed.

Next, use one of these digest-bound cross-references to select a concrete unresolved behavior question, checking its callsite and data dependencies before assigning a semantic name.
