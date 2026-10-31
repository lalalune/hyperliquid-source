# RE-017-abci-state-link-94

Standalone packet. `tools/abci_state_link.py` builds `abci-state-link.json` from node #94 bytes (Python standard library only): the RELATIVE relocation that fills GOT slot 0x57755a8 with 0x3273810, a whole-section `e8`/`ff15` caller pass, FDE extents, the `l1/src/abci/state.rs` line 107 col 37 Location at 0x56dfbf8, and 33 fixed instructions of 0x3273810 plus its call site 0x3272785. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/: it checks 33 key VAs byte by byte, re-derives 8 call/lea targets, re-hashes the 0x3273810..0x327396c extent, re-parses 2 relocations and the Location record, and re-runs the caller pass (7 sites across 3 pinned targets), then reports PASS, FAIL or INCONCLUSIVE. `tests/test_abci_state_link.py` holds the pins, seed/-O checks, negative controls and tamper tests. See EVIDENCE.md.

Finding (bytes only): 0x32725d0 calls `[0x57755a8]` at 0x3272785 -> 0x3273810 (reloc-only, 0 rel32 callers), which passes its args to 0x3c155a0 with the state.rs:107 Location, returns `{2, word}` when the first result word is 2, and otherwise calls `[0x5773aa8]` at 0x3273920. Slot 0x5773aa8 is the RE-016 materializer slot.

## Rerun

```
python3 -I -B research/work-items/RE-017-abci-state-link-94/verify.py
python3 -O -B research/work-items/RE-017-abci-state-link-94/verify.py
python3 -B research/work-items/RE-017-abci-state-link-94/independent_verify.py
python3 -B -m unittest tests.test_abci_state_link
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/abci_state_link.py | sha256sum; done
```

## File hashes

- EVIDENCE.md 32412c998db3ec99c417a8d7f3131c2c4d8b5f6c0847058f33b3ac5af590d0c7
- abci-state-link.json e8e24678b2e9aa32e93a08f5ab9e469b49b40742d2839affb1c9c2295ace4548
- verify.py 9c0b727200e9aa5058d92179a04322cd27eebb3dcaba4c19d90c46073709026f
- independent_verify.py 261d5442f9b74a068cf9e321433f32038b6613902638ab876050477c01a5a95e
- tools/abci_state_link.py e175c2cf67bea50e8cb7eef00e4a64e4f757439d62bde43d9a5c68450d5e59f3
- tests/test_abci_state_link.py 5b7a5b0e8e9526ccfe58fdf086950b27a4b6f210727a75e1f6e680d0237b61da

## What this does not claim

- It does not claim that value 2 is a Rust `Err` tag, or what 0x3c155a0 computes. Both are inference.
- It does not claim what 0x3751e80 does (RE-016) or what the five other `ff15 [0x5773aa8]` callers do.
- It does not claim the meaning of the copied 0x1fc8 / 0x20 / 0x30-byte blocks, or that 0x32725d0 runs on any particular node path.
- The caller pass covers `e8` and `ff15` only, in .text/.init/.fini/.plt. Zero counts are upper bounds for those forms only.
- Node #115 and other releases are not covered.
