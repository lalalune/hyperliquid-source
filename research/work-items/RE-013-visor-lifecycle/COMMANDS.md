# RE-013 command record

All commands were run from the repository root.  The captured visor was read as
data only.  Paths in retained disassembly are replaced with
`<authenticated-visor>`.

```sh
git fetch origin
git rev-parse origin/main
# 1f8c67c63ca4794c9689235471c60297f8a5c985

shasum -a 256 artifacts/visor/captured/hl-visor
# 89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31

python3 tools/visor_lifecycle.py \
  --binary artifacts/visor/captured/hl-visor \
  --output research/work-items/RE-013-visor-lifecycle/records \
  --disassembler llvm-objdump

python3 -m unittest tests.test_visor_lifecycle -v
make verify
make test
make catalogue-check
git diff --check
```

Tool versions used for the retained exports:

```text
Python 3.9.6
Apple LLVM version 21.0.0 (llvm-objdump)
git version 2.56.0
```

The final check results and sanitized output hashes are recorded after the full
matrix in `validation.md`.
