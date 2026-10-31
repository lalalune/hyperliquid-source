# RE-016 state chain (hl-node #94)

This is a standalone packet. `tools/state_chain.py` builds `state-chain.json` from the binary. It needs only a bounded .rela.dyn parse and three bounded function extents. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/. It checks 43 key VAs byte by byte, re-derives 10 call/slot targets, re-parses both relocations and re-runs the whole-section e8/ff15 caller pass (8 sites across 5 pinned targets), then reports PASS, FAIL or INCONCLUSIVE. `tests/test_state_chain.py` holds the pins, the seed checks and the tamper tests. See EVIDENCE.md.

File hashes (also in MANIFEST.sha256):

- EVIDENCE.md 9973ca95ae6e4b301b98c5e0b486f2f381da9e2ce90bb280775d611b3cbb6baa
- state-chain.json 6e063821c3de3ad62dc45b0af1bc28ff7cdedaf048da0fbdd3cc5e51cabead75
- verify.py 9f48f7929400ee00e5822c81512a5e06a9023defd8e9907796636d510ed39ac9
- independent_verify.py fc9d1532fb9654bd099c5ae6d679a916c1eed84c53483bf0bc1173f760d5be70
- tools/state_chain.py e943f1a288d2980b420ad6a399d1b0df007c548d7624eb765ced089f27888a81
- tests/test_state_chain.py 60a186e5789f4f365d310e5fd624d13b7c360510c026942c34839eaf1c421cd2

## What this does not claim

- It does not prove that 0x3751e80 builds a snapshot or an export. "State materializer / exporter" is inferred. No string literal is referenced in the three extents, and no named caller exists.
- It does not identify which caller reaches 0x3751e80. Six indirect `ff15` call sites load slot 0x5773aa8, proven by the packet's own caller pass over .text/.init/.fini/.plt (which also proves 0 rel32 callers of 0x3751e80 and 0x326e460, and the single rel32 caller 0x3752220 of 0x3270570).
- It does not describe 0x3269ae0 beyond "the top LtHash fn, documented in #262/#316". It does not describe 0x37d08a0, 0x332d440 or 0x37d4e30 at all.
- It does not say what any copied block or field means. It records only lengths and destinations.
- It does not repeat #316's writer analysis, #262's LtHash analysis or #271's exchange +0x3a00 lead, and makes no claim over them.
- It makes no claim about other releases, source code or consensus behaviour, and it does not reimplement or compare anything.
