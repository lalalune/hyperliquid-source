# RE-017: Carry the local startup rewrite into the first converted #115 fixture

The named checkpoint and original compact state image supply the previous hardfork version and round, Context round and optional scheduled freeze height. The bridge pins both inputs and checks their selected fields agree. It then applies the reconstructed local-startup rewrite and supplies the resulting pair to the first-conversion fixture. The archive hardfork pair must agree with that rewritten pair. The full original Context at H and the four selected H+1 begin fields are compared by the existing runner. This bridge also checks both hardfork child digests inside the verified H+1 raw reference. [Named checkpoint reader](https://github.com/lalalune/hyperliquid-source/pull/7580) · [Compact-image rewrite](https://github.com/lalalune/hyperliquid-source/pull/7594) · [First converted fixture](https://github.com/lalalune/hyperliquid-source/pull/7645)

The synthetic checkpoint at height 42 stores hardfork pair `[5,17]`, Context round 40, and scheduled freeze height 42. The freeze-at-H path changes the replay pair to `[6,40]`. The Context round stays 40 as the converter baseline. Nine empty recorded payloads are skipped, and the tenth yields height 43 and admitted round 50 with the materialized replay pair. The original H reference matches; all four H+1 begin leaves and both hardfork children match. A self-consistent H+1 raw reference that retains the original pair still passes the previous four begin checks, while both new hardfork comparisons differ. An archive that retains the original hardfork pair is also rejected.

The reference trees are synthetic and use independently chosen field values. The selected hardfork comparison covers the local rewrite's two words. Full state transitions and production H/H+1 parity require additional evidence. The pinned ELF is read as data while running the existing startup, cursor, header and root evidence checks. The verifier only runs reconstructed Python and offline Rust. Target node #115 Linux x86-64 SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with msgpack 1.1.2 and Rust 1.95. The exact source snapshots listed in the verifier must be available in the local Git object database.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

For a supplied case, start from the [first-conversion manifest](https://github.com/lalalune/hyperliquid-source/pull/7645). Replace `restored_round` and `ordered_pair` with a `compact_image` artifact entry containing a relative `path` and whole-file `sha256`. The compact image is the original decoded state before local rewrite. The report records the original and revised pairs, the materialized image digest, the selected wire header, and the separate H+1 hardfork comparison. The [offline log](offline-log.txt) records the actual static and synthetic verification output.
