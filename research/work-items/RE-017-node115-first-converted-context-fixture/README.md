# RE-017: Select the first converted #115 Block before verifying H+1

An ordered replay capture can start with a Block that matches the restored identity and still produces no ordinary conversion output. The native cursor advances its expected identity when it observes an ordinary empty record below the cutoff-plus-ten threshold, while retaining its conversion cutoff. The adjacent Context fixture expects the caller to supply the already converted Block. This adapter runs the existing reconstructed cursor on the pinned ordered records and uses its first converted payload and actual cutoff as that input. [Conversion cursor](https://github.com/lalalune/hyperliquid-source/pull/7381) · [Wire-to-Context fixture](https://github.com/lalalune/hyperliquid-source/pull/7611)

The synthetic case starts at checkpoint height 42 and restored consensus round 40. Nine empty records advance the expected identity while keeping cutoff 40. The tenth has successor round 50 and reaches the conversion threshold. The wire archive comparison and selected Context root checks then use sequential height 43, admitted round 50 and converter parent round 40. The archive row and synthetic H+1 reference use independently supplied values. A control supplying the earlier skipped row's archive metadata fails the wire comparison. A previous missing capture fails the identity check. An exhausted capture with nine skipped rows reports that no conversion was available. A mismatching initial round is rejected against the pinned checkpoint.

The Rust cursor probe supports ordinary direct-quorum input. Its prepared-owner count comes from the manifest so the caller can supply the observed input count before native row filtering. The ordinary fixture verifies the supplied restored round against the pinned named checkpoint before cursor use. Startup paths that rewrite the initial round remain a separate fixture boundary. It does not infer missing captures, validate production provenance, execute actions or attest complete H/H+1 state-root parity. The pinned ELF and the 35 cursor and 119 header instruction witnesses are checked as static data. Target node #115 Linux x86-64 SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory and use Python with msgpack 1.1.2 and Rust 1.95. The exact source objects listed in the verifier must be available locally.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

For a supplied case, keep the `height`, `ordered_pair`, `archive`, `checkpoint_rmp`, `reference_h`, and `reference_h_plus_one` fields from the wire case. Replace the single `wire` and `conversion_cutoff` fields with the explicit `restored_round` and ordered `records` list. Each record supplies `path`, `sha256`, and `prepared_count`. Paths are relative to the manifest. The report includes input SHA-256 and both cursor values per observed position, and shows the precise converted payload's successor metadata and selected root comparison. The [raw offline output](offline-log.txt) records the exact verifier run.
