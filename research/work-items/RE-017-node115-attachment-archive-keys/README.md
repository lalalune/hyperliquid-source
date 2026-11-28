# RE-017: Bind converted archive bundle keys to decoded source rows

The decoded Block carries attachment keys and their opaque bytes. The ordinary replay converter retains the original 32-byte keys only for rows reporting successful conversion. The archive writer emits those retained keys in order as the first item of each `signed_action_bundles` tuple. This fixture compares the archive keys against the selected positions of independently verified decoded source attachments. [Attachment fixture](https://github.com/lalalune/hyperliquid-source/pull/7396) · [Related bundle count check](https://github.com/lalalune/hyperliquid-source/pull/7359)

The native converter at `0x4fad300` reads both 16-byte halves of each source row, compares the selected conversion result to `0x1a2`, and only then writes the saved 32-byte key into a 40-byte output slot. It returns the vector pointer and count at `+8/+0x10`. The worker's selected ordinary record path clones every complete retained row in the same order through `0x5a6eb86..0x5a6eba5` and passes the resulting tuple-array descriptor to the archive serializer. The final writer passes the row base and a 32-byte length to its hex adapter.

The fixture accepts a separately reported list of successful source positions. It verifies the original decoded attachment count, content digest and ordered header digests using the existing Rust adapter. A three-attachment synthetic record selects rows zero and two, then verifies these two keys in the archive. Controls reject the reversed key order and an extra omitted row in the archive. An independently empty selection matches an empty archive. The synthetic payloads exercise only opaque structural decoding. Actual conversion success, application results and state roots require independent observations.

The verifier authenticates 62 selected #115 ELF instruction spans, the selected relocation and literal addresses, and checks the reconstructed Rust decoder offline. Target Linux x86-64 #115 SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The binary is read as data.

## Reproduce

From the repository root, set `packet` to this directory. Use Rust 1.95, Python with PyCryptodome 3.23.0, and the exact decoder source snapshot in the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The manifest contains the explicit archive `height`, `wire` and `archive` artifact entries with relative `path` and SHA-256, and an increasing `successful_rows` list of observed zero-based source positions. See the [raw offline output](offline-log.txt).
