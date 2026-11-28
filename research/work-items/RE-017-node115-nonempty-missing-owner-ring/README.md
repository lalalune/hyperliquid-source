# RE-017: Read nonempty omitted #115 attachment owners from a supplied ring

The earlier handoff trace covers present attachment owners and the absent-owner branch with no requested digests. This packet follows the selected nonempty missing-owner branch through the ordinary flat lookup and row materializer. A caller can supply an independently captured fixture ring and a pinned Block payload, then verify lookup order and identify a missing content key without running the captured ELF. [Earlier owner handoff](https://github.com/lalalune/hyperliquid-source/pull/7273) · [Existing flat search](https://github.com/lalalune/hyperliquid-source/pull/2716) · [Independent attachment body staging](https://github.com/lalalune/hyperliquid-source/pull/7730)

On the selected worker path, `0x5a8750c` forms F+0x128 in RCX. `0x5a87a64` passes that store to `0x4fad710` with the Block and its absent optional attachment-owner pointer. The helper reads the Block's key vector pointer and count at +0x18/+0x20. It walks those keys in 32-byte steps and passes the selected store at RCX+0x20 to the known flat search at `0x57f5ee0`. An ordinary hit has a logical index within the store's live bound. The helper adds the head, wraps by the capacity, then reads the stored opaque word at physical row +0x20. Both halves of the original query key and the selected word are carried into the appended 40-byte row. The final result carries the newly collected owner. If lookup fails, the selected branch carries the first missing 32-byte key in a tag-`0x1c` result and does not return a completed owner.

The Rust fixture reuses the existing verified flat ring search on supplied keys and opaque identifiers. Four queries to a wrapped three-row ring produce physical indices 1, 3, 0 and 3 in input order. A separate three-query probe finds an initial hit, then identifies the first missing key with no successful rows in its report. Reference count mutation, lifetimes, scheduling, cache population, the alternate tree lookup, and production root verification remain separate. The fixture never treats supplied integers as native pointers.

The verifier checks 72 exact spans, indexed FDEs, selected relocations and branch outcomes against Linux x86-64 #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It runs only reconstructed offline Rust and Python.

## Reproduce

From the repository root, set `packet` to this directory with Rust 1.95 and the exact source snapshot in the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --wire BLOCK.bin --wire-sha WIRE_SHA256 --ring STORE.txt --ring-sha RING_SHA256
```

The supplied ring text starts with decimal head and live length. Each remaining physical row contains a 64-digit hexadecimal key and a decimal opaque identifier. The fixture requires an ordinary complete Block with nonempty requested keys and an absent attachment owner. See the [raw offline output](offline-log.txt).
