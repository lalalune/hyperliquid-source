# RE-018-materializer-call-abi-94

Standalone packet. `tools/materializer_call_abi.py` builds `materializer-call-abi.json` from node #94 bytes (Python standard library only): a whole-section `ff15` pass for GOT slot 0x5773aa8, the FDE start of each site, and — for the five contested callers outside 0x3273810 — the pinned lea/mov/call/post bytes plus a [-0x40,+6) window hash. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/: it checks 38 key VAs byte by byte, re-derives 5 call targets, re-hashes 5 windows, re-runs the caller pass (6 sites), and reports PASS, FAIL or INCONCLUSIVE. `tests/test_materializer_call_abi.py` holds the pins, seed/-O checks, negative controls and tamper tests. See EVIDENCE.md.

Finding (bytes only): each of 0x226685a, 0x2268f61, 0x4359d34, 0x4746097 and 0x4b2c8e2 loads four pointers into rdi/rsi/rdx/rcx and calls `[0x5773aa8]`. The sixth site 0x3273920 is cited from RE-017, not re-owned.

## Rerun

```
python3 -I -B research/work-items/RE-018-materializer-call-abi-94/verify.py
python3 -O -B research/work-items/RE-018-materializer-call-abi-94/verify.py
python3 -B research/work-items/RE-018-materializer-call-abi-94/independent_verify.py
python3 -B -m unittest tests.test_materializer_call_abi
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/materializer_call_abi.py | sha256sum; done
```

## File hashes

- EVIDENCE.md 873252fe4e8631e13944d9d80f3a381235c54541cda11b0b8c8af41aac57dacd
- materializer-call-abi.json 4789cdd0cb2dd7af93b0a20b50cd976da3b3fc18fe0307505d0b25a98c6f52f0
- verify.py 4987057e4ae85727fe51b5b985d693f74a82a5275e893acfd0bb1931d002eb8e
- independent_verify.py ab8cc47dbdeb1bf1e5db86fc68581d15edf8398d1edb7e68bd77a00139252ba3
- tools/materializer_call_abi.py c133cb4f6f794c6752569d29b3520b51e143edc81ddc15a75af0a47ce5160597
- tests/test_materializer_call_abi.py 08c454c971fac42c66ace10b26885a27f192f0d063d52cdb01c0c0a258d8eb1f

## What this does not claim

- It does not claim that the four pointers match RE-017's buffer roles, or what the post-call flag bytes mean. Those are inference.
- It does not claim what 0x3751e80 does (RE-016) or re-analyse 0x3273920 (RE-017).
- It does not claim whole-FDE hashes or the transport/RocksDB/timeout facts already claimed by open PRs and RE-009 inside these FDEs.
- The caller pass covers `ff15` only, in .text/.init/.fini/.plt.
- Node #115 and other releases are not covered.
