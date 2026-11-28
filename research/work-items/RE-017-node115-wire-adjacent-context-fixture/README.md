# RE-017: Drive the adjacent Context-root fixture from a decoded #115 Block

The [adjacent Context runner](https://github.com/lalalune/hyperliquid-source/pull/7465) restores the named MessagePack Context and verifies its selected H/H+1 fields against two complete raw reference trees. Previously that runner needed an already prepared successor-header JSON file. This adapter derives the header from a pinned ordinary completed replay payload, checks its clock and rounds against the separately pinned native archive row, and then runs the existing Context comparator. It also requires an explicit archive height of H+1 independently of the consensus round. The [existing archive header audit](https://github.com/lalalune/hyperliquid-source/pull/7568) checks additional header fields and can still be used separately.

The Rust probe calls the [existing Block decoder and header projection](https://github.com/lalalune/hyperliquid-source/pull/7370). It requires the original wire prefix to be fully consumed and the caller's ordered comparison pair to match. The adapter uses the decoded signed-year and ordinal representation, second-of-day and nanoseconds to derive the normalized successor clock. It independently parses the archive timestamp through the existing checkpoint normalizer and rejects differing times or rounds. Only that verified height, admitted round, and decoded clock reach the root comparator. The adapter expects ordinary date/time values supported by the existing comparator, with years 1–9999 and no leap-second representation.

The reproducible example uses synthetic H=42 and H+1=43 at rounds 40 and 41. A restored current clock immediately before the Unix epoch rotates to the decoded clock of epoch plus 120 ms. The original checkpoint matches all thirteen modeled Context leaves. The H+1 reference passes the four begin-field checks for height, round, current clock and previous clock. A second internally consistent H+1 reference differs by one nanosecond and fails only the current-clock comparison. Separate controls reject an archive height equal to the round and an archive timestamp inconsistent with the wire. The two raw reference trees use independently specified expected Context values and the same checked hash codec. These are synthetic regression vectors, not production observations or evidence of full state-root parity at H+1.

The verifier independently rechecks the pinned ELF digest and the existing native decoder, encoding and height-advance witnesses. It reads the Linux x86-64 node #115 capture as data and executes only offline Python and reconstructed Rust. The capture SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, use Python 3.9 or later with msgpack 1.1.2, Rust 1.95 and the exact snapshots listed in `verify.py` in the local Git object database. Set `packet` to this directory.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

For a supplied case, the manifest has unsigned `height`, unsigned `conversion_cutoff`, the two unsigned terms of `ordered_pair`, and five SHA-256-pinned entries with `path` and `sha256` keys. Paths are interpreted relative to the case manifest. The roles are `wire` for the complete plain payload, `archive` for one native-shaped JSONL row, `checkpoint_rmp` for the named checkpoint, and `reference_h` and `reference_h_plus_one` for the matching raw-export rows. Values such as the cutoff and binary producer identity require separate evidence. The last two output JSON lines show the verified wire-derived successor header and the selected root-comparison report. A valid selected mismatch yields exit 1. See the [raw offline output](offline-log.txt).
