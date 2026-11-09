# RE-017: trace node #115 digest-quorum mismatch formatting

- Component ID: `abci` / replay comparison boundary.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: target-bound static observations; the role of the mismatch payload is an inference from its call path and writes.
- Scope: resolve slot `0x64df6e8` inside the selected compact-row comparison helper at `0x1546570`; distinguish its mismatch output from descriptor and row input data.

This follows the descriptor-associated row path in [#5559](https://github.com/lalalune/hyperliquid-source/pull/5559) and the bounded hour helper in [#5715](https://github.com/lalalune/hyperliquid-source/pull/5715). The latter leaves slot `0x64df6e8` unresolved. [#4460](https://github.com/lalalune/hyperliquid-source/pull/4460) independently observes this slot in a different formatting callsite; this packet binds it to the comparison helper's mismatch branches and output object. It also addresses the remaining descriptor-consumer question proposed in [#5391](https://github.com/lalalune/hyperliquid-source/issues/5391).

## Findings

The caller FDE extent is `0x1546570..0x15466f3`; the target's unwind extent is `0x141e3a0..0x141e538`. These are unwind ranges, not validated source-function boundaries. The `.rela.dyn` row at slot `0x64df6e8` has symbol index 0, type 8, and addend `0x141e3a0`. On ELF x86-64, type 8 is `R_X86_64_RELATIVE`; the callback target is therefore statically derivable from the pinned file without reading a relocated process address.

The helper first reads the row's 32-bit key and descriptor bytes at `+0xa8` and `+0xa9`, then may call the separately resolved hour helper through `0x64e0f58`. The selected equality branches return without calling `0x64df6e8`. On mismatch branches, the helper instead builds a local formatting argument record and calls `0x64df6e8` with an output buffer pointer, an encoded template pointer, and the argument record. The two template byte sequences are:

| Template VA | Exact bytes | Readable literal bytes |
|---|---|---|
| `0x43ab07` | `c0 08 2f 68 6f 75 72 6c 79 2f c0 01 2f c0` | `/hourly/` |
| `0x43aa84` | `c0 01 2f c0` | `/` |

The `0xc0`-prefixed encoding is retained as raw bytes; this packet does not assign source-level formatting syntax to its markers. After each callback, the caller copies the produced local value into its output record. It also writes the row key and a one-byte branch discriminator; the first mismatch arm additionally stores the hour-helper result byte. The selected code reads descriptor fields and row data to construct that result, but the callback is not passed the descriptor pointer or incoming row pointer as its output destination.

This bounds the callback's role on the selected path to mismatch-result construction. It does not establish the output type's complete layout, the meaning of either template beyond its literal bytes, callback effects outside the inspected FDEs, runtime branch frequency, builder semantics, root provenance, persistence, or replay success. No component gate is advanced.

## Reproduction

The packet verifier uses only Python's standard library plus the repository's static ELF/FDE parsers. It checks the pinned artifact digest, both exact FDE extents, complete FDE byte windows, relocation tuples, template bytes, and five corruption controls. The recorded disassembly was produced with Apple LLVM `llvm-objdump` 21.0.0 on macOS arm64; Python was 3.14.3. The captured binary was read only and never executed or emulated.

From repository root:

```sh
python3 research/work-items/RE-017-node115-digest-quorum-mismatch-format/verify.py --write
python3 research/work-items/RE-017-node115-digest-quorum-mismatch-format/verify.py
xcrun llvm-objdump --disassemble --start-address=0x1546570 --stop-address=0x15466f3 artifacts/node/115/hl-node
xcrun llvm-objdump --disassemble --start-address=0x141e3a0 --stop-address=0x141e538 artifacts/node/115/hl-node
python3 tools/verify_packets.py
```

`--write` regenerates the packet's compact byte snapshot only after checking the fixed target digest and expected addresses, relocations, and literals. The default command rechecks that snapshot against the target and rejects altered evidence. The target's retained SHA-256 and signature were checked against the repository public key; the signed artifact's key fingerprint is `CF2C2EA3DC3E8F042A55FB6503254A9349F1820B`:

```sh
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'tools')
import artifacts
root = Path('.')
manifest = artifacts.load_manifest(root)
paths = {'artifacts/node/115/hl-node', 'artifacts/node/115/hl-node.asc', 'artifacts/keys/pub_key.asc'}
files = [item for item in manifest['files'] if item['path'] in paths]
assert {item['path'] for item in files} == paths
for item in files:
    artifacts.check(root / item['path'], item)
artifacts.verify_signatures(root, {'files': files, 'signing_fingerprint': manifest['signing_fingerprint']})
PY
```

The packet verifier passed with 2 FDE extents, 2 complete code windows, 3 relocation rows, 2 template byte strings, and 5 rejected corruptions. `tools/verify_packets.py` passed in the sparse checkout with 2 manifests / 9 entries. Repository-wide `make verify` did not complete in the sparse checkout: after confirming the node binary and signature files' hashes, it stopped because `artifacts/node/115/node_metadata.json` was not materialized. `make doctor` reported GNU `objdump`/`readelf`, Java, and Ghidra unavailable; Apple LLVM was used directly through `xcrun`. No repository tooling or generated catalogue was changed.

## Limits and next question

This packet resolves one callback use, not the descriptor-associated builder's full behavior. Next, determine how the builder consumes the comparison result variants and whether any resulting state is later read as a reference value, keeping that path separate from context `+0x400` history lookup.
