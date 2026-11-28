# RE-017 attachment body provenance after #115 owner lookup

An omitted-owner Block carries a list of content keys. The verified ring and tree lookups produce one opaque object identifier per key. The raw-body staging fixture separately checks content against the decoded Keccak-256 keys. This adapter binds those observations so that each staged body must come from the exact opaque identifier selected by the store. [Flat store lookup](https://github.com/lalalune/hyperliquid-source/pull/7767) · [Tree store lookup](https://github.com/lalalune/hyperliquid-source/pull/7774) · [Raw-body staging](https://github.com/lalalune/hyperliquid-source/pull/7730)

The case manifest pins the original Block wire, a ring or tree observation and an identifier-indexed body catalog by SHA-256. Each selected identifier resolves to a catalog entry. The existing staging verifier re-decodes the original wire, checks the selected files against their SHA-256 and the corresponding wire keys against Keccak-256, then emits one file per position in the original order. Repeated keys keep both positions. An unresolved store key returns the first missed key without staging files. A missing catalog identifier or an independently SHA-valid but swapped association also leaves no output.

The default probe uses synthetic body bytes and logical identifiers with a wrapped ring and a tree that exercises both child directions and a separator lookup. It checks the exact native spans via the earlier verifiers, compiles the local Rust decoder offline, and runs the Python fixture. The captured Linux x86-64 ELF remains input data. These fixtures establish offline compatibility of the lookup and staging boundary. Loading actual native objects and validating production replay remain separate.

## Reproduce

Use Rust 1.95, Python 3.9 or newer, and PyCryptodome 3.23.0. Run from the repository root with the three input PR commits available locally. The verifier stages the exact commits named in its source.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256 --output NEW_DIRECTORY
```

The case has three fields. The `wire` object carries `path` and `sha256`. The `store` object adds a `kind` of `ring` or `tree` and uses the linked observation format. The `bodies` list uses `id`, `path`, and `sha256` per entry. Paths can be relative to the case file. Keep the original Block, store observation and body catalog as separate inputs. The [raw offline output](offline-log.txt) shows the selected identifiers, source key order, hashes and rejection results.
