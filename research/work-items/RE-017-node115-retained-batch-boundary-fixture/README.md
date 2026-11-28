# RE-017: Preserve retained batch boundaries before the first #115 conversion

The native retained helper starts a batch with an expected identity and an absent prior fingerprint. After an ordinary row is published, the publisher updates its baseline to that row's successor. The subsequent rows inside the same batch compare both identity and predecessor bytes. The offline adapter lets a caller supply two or more observed retained batches in publication order. It uses the existing canonical comparison only within each batch, checks each observed initial baseline reached by the cursor, and submits the unchanged ordered records to one first-conversion cursor. [Retained validator](https://github.com/lalalune/hyperliquid-source/pull/7306) · [Publisher baseline](https://github.com/lalalune/hyperliquid-source/pull/7286) · [Single-batch fixture](https://github.com/lalalune/hyperliquid-source/pull/7646)

The synthetic corpus uses two batches at baselines 40 and 44. The first has four rows and the second has six. It verifies eight within-batch fingerprint links. The converter's numeric identity continues from the preceding row, and its cutoff remains 40 through the boundary. The tenth row is the first conversion at height 43 and round 50, and the existing selected Context checks pass. Changing only the declared second baseline fails. Treating the two observed groups as one creates an unsupported fingerprint comparison at the old boundary and fails the fixture.

Batch membership and baseline observations are caller inputs. The report distinguishes the batch starts actually reached by the cursor before first conversion. The bridge models same-batch fingerprint checks and the supplied publication order. Actual scheduling, signing, chain provenance, and complete state parity require separate evidence. Synthetic inputs are ordinary structurally decoded direct-quorum records with empty vote lists. The verifier checks the selected publication instructions and subsequent native evidence using the Linux x86-64 #115 ELF as data. Target SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory and use Python with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95, and the exact source snapshots listed by the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

For a supplied case, start with the [linked fixture manifest](https://github.com/lalalune/hyperliquid-source/pull/7646) and replace its `records` list with a `batches` list. Each element has an observed unsigned `baseline` and an ordered nonempty list of the original `records` entries. The report gives independent batch-start and within-batch checks in addition to the original conversion and Context results. See the [raw offline run](offline-log.txt).
