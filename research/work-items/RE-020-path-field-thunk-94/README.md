# RE-020: path-field layout in FDE 0x22ae8a0 + GOT thunk 0x4546ba0 (node #94)

## Claim

Inside FDE `0x22ae8a0..0x22b1080` there are exactly four `ff15` call sites through
GOT slot `0x5773c70`. Each loads its path pointer from a different source:

| site | path-pointer source | proving load |
|------|---------------------|--------------|
| `0x22aec0f` | `[rbp+0xd0]` | `0x22aebc6` `48 8b b5 d0 00 00 00` |
| `0x22aee86` | `[rbp+0x140]` | `0x22aee6e` `48 8b b5 40 01 00 00` |
| `0x22aef33` | `[rbp+0x220]` | `0x22aef22` `48 8b b5 20 02 00 00` |
| `0x22afc2c` | `r15` | `0x22afc29` `4c 89 fe` |

GOT `0x5773c70` is a single `.rela.dyn` RELATIVE whose addend is `0x4546ba0`.
That FDE (`0x4546ba0..0x4546c60`) is a thin thunk: it preserves `rsi`/`rdx`
(path pointer/length), injects `lea rcx, Location 0x56dfc28` (state.rs:86),
redirects `rdi` to a local out buffer, then `e8` to the loader at `0x3c155a0`.
Whole-section census: exactly 4 `ff15` through the slot; exactly 0 direct `e8`
to `0x4546ba0`.

## What this does not claim

- Which filename or format string each path field (`+0xd0` / `+0x140` / `+0x220` / `r15`) holds.
- Who writes the path fields at `+0xd0` / `+0x140` / `+0x220` (later scouting job).
- Internals of the loader at `0x3c155a0` (see RE-019).
- The meaning of neighbouring GOT slots.

## Reproduce

```
python3 -I -B research/work-items/RE-020-path-field-thunk-94/verify.py
python3 -O -B research/work-items/RE-020-path-field-thunk-94/verify.py
python3 -B research/work-items/RE-020-path-field-thunk-94/independent_verify.py
python3 -B -m unittest tests.test_path_field_thunk
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/path_field_thunk.py | sha256sum; done
python3 -O -B tools/path_field_thunk.py | sha256sum
```

Tool: Python 3 standard library only (no objdump, no pyelftools). Target:
`artifacts/node/94/hl-node` sha256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
