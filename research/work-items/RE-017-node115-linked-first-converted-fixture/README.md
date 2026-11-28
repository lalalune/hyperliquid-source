# RE-017: Check retained predecessor links through the first converted #115 Block

The retained validator checks successive Block identities and predecessor hashes before the converter's later empty-record decision. The first-conversion fixture models the numeric cursor and then compares the selected Block to archive and Context references. The bridge first checks both native comparison operands for every adjacent pair in a caller-supplied retained batch. It derives each predecessor fingerprint from the actual preceding decoded payload, checks that against the current quorum hash, then uses the unchanged pinned payloads for conversion and Context comparison. [Retained validator trace](https://github.com/lalalune/hyperliquid-source/pull/7306) · [Decoded predecessor digest](https://github.com/lalalune/hyperliquid-source/pull/7625) · [First conversion fixture](https://github.com/lalalune/hyperliquid-source/pull/7645)

The synthetic batch covers consensus identities 40 through 49, with nine valid predecessor links. The first nine empty records stay below the cutoff threshold and the tenth yields the archive block at H+1=43, round 50 and parent cutoff 40. The H and H+1 selected Context fields match the synthetic references. A second synthetic batch changes only the incoming predecessor value of one of the skipped records. That batch still reaches the same round and matches the selected Context fields when using the scalar fixture by itself. The linked runner reports the predecessor mismatch between positions 2 and 3 before the conversion or Context stage runs.

The supplied order and same-batch membership are fixture inputs. The first record has no prior intra-batch fingerprint to compare, and the cursor still checks its initial identity. The current digest adapter supports the ordinary direct-quorum previous record with an empty vote list. The fixtures use structural placeholders and direct-quorum records throughout. Consensus admission, actual chain provenance, actions and complete reference-state parity are separate evidence.

The verifier reuses the exact existing snapshots for the pointer/field evidence, canonical digest and retained cursor. It reads the pinned Linux x86-64 node #115 ELF as data and runs only reconstructed Rust and Python. The target SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95, and the exact Git objects listed in the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The manifest follows the [first-conversion fixture](https://github.com/lalalune/hyperliquid-source/pull/7645), with all records supplied from one retained batch. Each record has its own whole-file SHA-256 and observed prepared-owner count. See the [raw offline output](offline-log.txt) for the selected static checks and measured success and mismatch results.
