# RE-017 use staged omitted-owner bodies for the first #115 conversion

The first-conversion fixture already takes the attachment count before filtering. The existing integration derives that count from bodies embedded in the source wire. For a Block with an omitted owner and materialized store objects, this adapter derives the same count from the verified body custody report. It passes the original SHA-256-pinned wire unchanged to the existing conversion cursor and checks the selected archive row against the supplied successful source positions. [Present-owner first-conversion fixture](https://github.com/lalalune/hyperliquid-source/pull/7739) · [Omitted-owner provenance](https://github.com/lalalune/hyperliquid-source/pull/7789) · [First-conversion cursor](https://github.com/lalalune/hyperliquid-source/pull/7645)

The test starts at synthetic checkpoint height 42 and round 40. The preserved original wire omits its owner and names two bodies. The observed tree resolves both. The measured count of two makes the cursor select the same Block immediately at round 41 and height 43. The separately supplied archive retains only the second body's key, in agreement with the one supplied successful position. The existing selected H and H+1 Context fields agree with the synthetic references. Changing the archive key breaks the key comparison while the Context comparisons still pass. Removing a required store key prevents selection, and supplying zero instead of the prepared count exhausts this one-record cursor.

Capture SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks earlier native evidence against the #115 Linux x86-64 file and runs reconstructed local Rust and Python. The adapter takes the successful positions as input. Native object recovery, action conversion, and full production state-root parity remain separate.

## Reproduce

Use Python 3.9 or newer with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95 and the exact locally reachable input commits in `verify.py`. From the repository root set `packet` to this directory.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The case takes the usual `height`, `restored_round`, `ordered_pair`, `archive`, `checkpoint_rmp`, `reference_h` and `reference_h_plus_one` inputs. Each `records` entry has a `wire` artifact and, for an omitted owner with nonempty references, a `materialization` artifact using the linked custody schema. Both artifacts carry `path` and `sha256`. `successful_rows` specifies the ordered zero-based positions observed for the selected record. [Raw offline output](offline-log.txt)
