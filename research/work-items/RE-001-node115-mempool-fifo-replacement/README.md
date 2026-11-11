# RE-001: node #115 mempool cache replacement preserves FIFO order

- Component: mempool cache; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: 2 complete FDEs, 1,328 bytes. Exact intervals and body digests are in `records.json`.
- Scope: the policy below, with unresolved helper boundaries retained. All component gates remain false.

## Finding

The upsert helper at `0x2cacdb0` stores an eight-byte key and a 32-byte payload. An existing key replaces its payload in place and does **not** append the key again. A missing key is inserted into the map and appended to the queue's wrapped tail. This is insertion-order eviction, not an access-refresh policy.

Both paths then compare the queue length at owner `+0x18` with a separate limit at owner `+0x40`. While length exceeds that limit, they advance the wrapped front, decrement queue length, read the old front key, and call `0x2dcb4b0` to remove that key from the map. Replacement can therefore evict entries when the current limit is below the queue length. A zero limit removes every queued entry, including a new insertion. Allocation or helper failure does not establish a completed update.

The owner queue uses capacity, pointer, front and length at `+0`, `+8`, `+0x10` and `+0x18`. The map descriptor begins at `+0x20`; `+0x40` is beyond it. For alternate map storage, occupied rows have 40-byte stride and the payload starts eight bytes into the row. Tree values use 32-byte stride. These are observed layouts, not recovered public type names.

The supporting removal body handles an alternate-storage miss without decrementing map length. On a found row it copies the row, invokes the shift helper, decrements map length and returns a present marker plus payload. The tree deletion, map lookup/insertion, growth and rebalancing algorithms remain opaque.

| Native interval | Observation |
| --- | --- |
| `0x2cacdc1..0x2cacdfd` | Map entry dispatch; occupied raw tag 1 |
| `0x2cace55..0x2cace99` | Existing payload replacement |
| `0x2cace99..0x2cacf0b` | Replacement path trims oldest queued keys |
| `0x2cacf10..0x2cacf99` | New map entry, queue growth if full, append, limit check |
| `0x2cacfb0..0x2cacffb` | Insertion path uses the same front-pop/removal order |

The full removal FDE is supporting context; its generic collection transitions are not a new research claim.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-mempool-fifo-replacement/export_disassembly.py
python3 research/work-items/RE-001-node115-mempool-fifo-replacement/verify.py --controls
python3 research/work-items/RE-001-node115-mempool-fifo-replacement/relations.py
python3 -m unittest discover -s tests -p 'test_node115_mempool_fifo_replacement.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-mempool-fifo-replacement/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2081](https://github.com/lalalune/hyperliquid-source/pull/2081) covered the parent mempool local-miss/found-conflict gates and left this callee opaque. [PR #2632](https://github.com/lalalune/hyperliquid-source/pull/2632) covered different mempool registry thresholds. [PR #613](https://github.com/lalalune/hyperliquid-source/pull/613) covered a predecessor walk. This packet's question is replacement versus insertion in the FIFO cache and the shared trimming policy.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
