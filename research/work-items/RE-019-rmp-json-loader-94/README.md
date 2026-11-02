# RE-019-rmp-json-loader-94

Standalone packet. `tools/rmp_json_loader.py` builds `rmp-json-loader.json` from node #94 bytes (Python standard library only): path ABI `(rdi=out, rsi=path_ptr, rdx=path_len, rcx=Location)`, the ~/ expander at 0x144a600 via GOT 0x576f628 (cmpw $0x2f7e), absolute-/ sete-flag (not reject), exact-.. branch to non-rmp arm, the FDE extent of 0x3c155a0, a whole-section e8 caller pass, the case-folded `.rmp` format gate, the two decode arms (rmp_serde::from_slice via 0x2e0db40 vs serde_json::from_str via 0x2fe2fe0), Ok length 0x1fc8 / Err tag 2, five diagnostic labels, and two Location records. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/: it checks 47 key VAs byte by byte, re-derives targets, re-runs the caller pass (3 sites), checks labels, Locations and the tilde GOT addend, and reports PASS, FAIL or INCONCLUSIVE. `tests/test_rmp_json_loader.py` holds the pins, seed/-O checks, negative controls and tamper tests. See EVIDENCE.md.

Finding (bytes only): 0x3c155a0 takes path ABI `(out, path_ptr, path_len, Location)`, expands `~/` via 0x144a600, gates on a case-folded `.rmp` extension, and loads via MessagePack or JSON accordingly; exactly three e8 sites call it, each passing a state.rs Location. Absolute `/` is a sete flag (not Err); exact-`..` takes the non-rmp arm.

## Rerun

```
python3 -I -B research/work-items/RE-019-rmp-json-loader-94/verify.py
python3 -O -B research/work-items/RE-019-rmp-json-loader-94/verify.py
python3 -B research/work-items/RE-019-rmp-json-loader-94/independent_verify.py
python3 -B -m unittest tests.test_rmp_json_loader
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/rmp_json_loader.py | sha256sum; done
```

## File hashes

- EVIDENCE.md 36cdb6e3def890ace2be529c938cf201bb17871a06f37ac96ad9397c20909c02
- rmp-json-loader.json 47e98c9d78eceb2125b799b77c89ce5c9f2a1353d7e7ec2aa24304578decd295
- verify.py b6b862c407186f9518846a58c28554ad46d5481947cc3a295d61cd4523cc3cd9
- independent_verify.py ba90c27819bbbb225fbb5331d1b4301dd83785d04917016a0a5011a0cb57109f
- tools/rmp_json_loader.py c449c7e394b2c3eff42bf4be44c80c30e191d779351cec91367510d2ca468211
- tests/test_rmp_json_loader.py bdc27a6b8f8d94415d7b56481d62d02b4344bf7fc1266f5bf5c5fdccf9dbbfc3

## What this does not claim

- It does not claim that absolute `/` or `..` are rejected to Err (bytes show sete-flag / non-rmp branch instead).
- It does not claim that Result tag 2 is a Rust `Err` discriminant, or what the 0x1fc8-byte Ok payload means at each caller. Those are inference.
- It does not claim the body of 0x3273810 / 0x3273920 (RE-017), the GOT chain through 0x5773aa8, or what 0x3751e80 does (RE-016).
- It does not claim exclusive ownership of the shared `serde_json::from_str:` diagnostic string at 0x1fd0ce (#365 cites the same string).
- The caller pass covers `e8` only, in .text/.init/.fini/.plt.
- Node #115 and other releases are not covered.
