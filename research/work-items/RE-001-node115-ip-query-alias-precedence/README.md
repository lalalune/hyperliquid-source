# RE-001: node #115 IP query preserves the original raw status over its alias

- Component: IP status query; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: 1 complete FDEs, 781 bytes. Exact intervals and body digests are in `records.json`.
- Scope: the policy below, with unresolved helper boundaries retained. All component gates remain false.

## Finding

The query at `0x4d56a00` looks up the original IPv4 address before an available alias. A found row yields `row_byte XOR 1`; a missing row yields raw `2`. An alias result replaces the original **only when the original raw status equals 2**. With canonical Boolean row bytes 0 and 1, a found original therefore wins over any alias result.

That statement needs the raw-status qualification: a noncanonical original byte 3 also maps to 2 and permits alias substitution. The exhaustive relation checks include every byte, not just the expected Boolean values. No meaning such as allow/deny is assigned to these raw statuses without a recovered type contract.

For RFC1918 addresses the routine consults a lazy table of eight-byte `(original, replacement)` pairs and uses the first match. Without a match, there is no alias query. For other addresses the alias is the original address itself. These translation rules are prior context, not the new finding. The query still visits an available alias even when a canonical original result will win. If the alias is missing, the original result remains. An empty tree root returns 2 immediately.

The tree path compares byte-swapped u32 keys, matching lexicographic network-byte ordering for the observed packed address representation. The alternate storage lookup calls `0x57f6b50`; its internals and the lazy translation initializer are unresolved. The two paths converge on the same row-byte transformation and raw-2 selection.

| Native interval | Observation |
| --- | --- |
| `0x4d56a0c..0x4d56a87` | Alias availability and translation context |
| `0x4d56a87..0x4d56b8d` | Original tree/alternate lookup and miss status |
| `0x4d56b8d..0x4d56bac` | Original row XOR 1; route toward alias |
| `0x4d56c43..0x4d56c88` | Empty tree / alternate alias lookup |
| `0x4d56c88..0x4d56ca0` | Alias XOR 1; substitute only for original raw 2 |

Valid map layouts, immutable lookup premises and canonical Boolean construction are separate assumptions. No live firewall behavior or complete IP policy is claimed.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-ip-query-alias-precedence/export_disassembly.py
python3 research/work-items/RE-001-node115-ip-query-alias-precedence/verify.py --controls
python3 research/work-items/RE-001-node115-ip-query-alias-precedence/relations.py
python3 -m unittest discover -s tests -p 'test_node115_ip_query_alias_precedence.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-ip-query-alias-precedence/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2520](https://github.com/lalalune/hyperliquid-source/pull/2520) covered the outer filter and left this query opaque. [PR #1378](https://github.com/lalalune/hyperliquid-source/pull/1378) covered the RFC1918 translation tables and rules; this packet credits that behavior as context. [PR #2852](https://github.com/lalalune/hyperliquid-source/pull/2852) concerns gossip admission. The new question is raw status selection and precedence between original and alias lookups.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
