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

- EVIDENCE.md d2ee27175bd1a9b388de61a5ff535afa38319ff708031a0abda241768f561e6f
- rmp-json-loader.json 58cf74dd36110d624b1df3422838f9f242c3ed14623a9b3bd44eb1e334ded75f
- verify.py c31f5236a287b0346dff09a9874a2a345c48647fe38a597d9b9e8daae4c5fbed
- independent_verify.py 0355dde46d97f479693fc05628be75e705b9c197692522fcc4b12dd851ec6777
- tools/rmp_json_loader.py aec96f293485c5831b7a172992bd8cc153d01e75010b193b0066a4084c502bd0
- tests/test_rmp_json_loader.py 3f30980e06f7b6a0ddaaa5d83455ee6375d0830ddb63766b194d72a6694376fa

## What this does not claim

- It does not claim that absolute `/` or `..` are rejected to Err (bytes show sete-flag / non-rmp branch instead).
- It does not claim that Result tag 2 is a Rust `Err` discriminant, or what the 0x1fc8-byte Ok payload means at each caller. Those are inference.
- It does not claim the body of 0x3273810 / 0x3273920 (RE-017), the GOT chain through 0x5773aa8, or what 0x3751e80 does (RE-016).
- It does not claim exclusive ownership of the shared `serde_json::from_str:` diagnostic string at 0x1fd0ce (#365 cites the same string).
- The caller pass covers `e8` only, in .text/.init/.fini/.plt.
- Node #115 and other releases are not covered.
