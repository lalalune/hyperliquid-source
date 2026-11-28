# RE-017: Preserve frame capture provenance through retained #115 replay

The offline linked fixture starts with one plain payload file per retained Block. A completed capture can instead contain a sequence of native five-byte frames with mixed plain and LZ4 payloads. This adapter verifies the full capture SHA-256, obtains each frame and its whole completed payload with the existing offline reader, and checks each against supplied independent pins. The report records offsets, frame and decoded sizes, compression mode, and both digests. The adapter passes the exact verified decoded bytes to the retained link and first-conversion fixture. [Framed replay decoder](https://github.com/lalalune/hyperliquid-source/pull/7408) · [Linked first-conversion fixture](https://github.com/lalalune/hyperliquid-source/pull/7646)

The synthetic fixture supplies ten framed Blocks using plain flags 0 and 2 and compression flag 1. Five compressed frames use literal LZ4 output with declared capacity larger than the actual payload. The verified intervals cover the full pinned capture. Every frame contains exactly one fully decoded Block. Nine predecessor links pass, and the tenth Block converts at sequential height 43 and round 50. The selected H and H+1 Context checks use the existing synthetic references. Independent controls reject a changed whole-capture pin, a raw frame digest from a different position, and a plain payload digest from a different position.

The verifier replays the existing static checks against the pinned Linux x86-64 #115 ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It runs only reconstructed Python and Rust using local, immutable source snapshots. Original capture direction, retention grouping, the prepared-owner counts, and production checkpoint and root provenance remain supplied evidence.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95, and the exact source snapshots in the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

For a supplied case, start with the [linked fixture manifest](https://github.com/lalalune/hyperliquid-source/pull/7646). Replace the individual `records` with a `framed_capture` object containing a relative `path`, whole-capture `sha256`, and a `frames` list in capture order. Each frame entry contains `frame_sha256` for the original header and body, `payload_sha256` for the exact completed payload, and `prepared_count` for the externally observed prepared-owner count. The output retains distinct capture, framing, payload and retained-link results. See the [raw offline run](offline-log.txt).
