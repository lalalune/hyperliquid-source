# RE-017: Use the prefilter attachment count to select the first #115 conversion

The empty-input cutoff checks the size of the incoming attachment owner. The converter appends only successfully converted rows to its archive bundles, so the archive count can differ from the original count. The fixture verifies the decoded owner and attachment bytes, derives the converter's input count, and records that separately from the independently observed successful source positions and archive output. It then checks the selected first conversion against the expected archive keys and adjacent Context references. [Native empty gate](https://github.com/lalalune/hyperliquid-source/pull/7381) · [Attachment owner handoff](https://github.com/lalalune/hyperliquid-source/pull/7273) · [Archive key comparison](https://github.com/lalalune/hyperliquid-source/pull/7715)

The synthetic first source record carries one verified attachment. The independent fixture supplies an empty successful-position list and zero archive bundles. With the original owner count of one, the converter selects this record immediately at successor round 41 and archive height 43. The H/H+1 selected Context values match. Supplying the archive's zero output count to the earlier count-driven fixture instead skips the only record because it falls below the empty-input threshold. This control establishes the distinct roles of those two counts.

Production attachment bytes, successful conversion positions, signatures, and the actual expected state roots require independent source material. This packet does not perform conversion of opaque action bytes. It reruns the pinned existing native checks and reconstructed Rust probes offline. The Linux x86-64 node #115 ELF digest is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; the binary is read as data.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95 and the exact local snapshots referenced by the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

Start from the [first-conversion input](https://github.com/lalalune/hyperliquid-source/pull/7645). The independently pinned `records` entries contain only original `path` and `sha256`; this tool measures the owner count. Supply `successful_rows` as the ordered observed positions in the selected converted Block. See the [raw offline output](offline-log.txt).
