# RE-017 #115 positional Context replay fixture ingress

The [named MessagePack projector](https://github.com/lalalune/hyperliquid-source/pull/7445) reads a Context map. This projector covers a different selected checkpoint form, where the outer `exchange` and `locus` wrappers remain named maps and their `ctx` value is a positional array. It streams one local checkpoint object, skips unrelated branches, and checks requested height, file digest and end of file.

The [positional replay-key analysis](../RE-017-node115-positional-context-replay-key/README.md) binds slots 2 and 4 to the distinct height and round words at decoded `+0x28/+0x30`. The [positional clock analysis](../RE-009-node115-positional-context-clock-pair/README.md) binds slots 5 and 6 to the current and previous clock, with selected minimum sequence presence checks through slot 8. The [MessagePack text path](../RE-009-node115-msgpack-clock-text-path/README.md) establishes the conversion boundary for both clock strings. This tool preserves the exact two selected clock texts and requires the ordinary positive-year calendar format without timezone or leap seconds. The remaining positional values are skipped and never interpreted as native Context fields.

When a separate digest-pinned `0x27a8`-byte decoded fixture is supplied, it must already carry the same height. The optional staging operation copies the projected round to `+0x30`. The verified composed output passes through the compact assembler and the loader’s distinct round-copy operations.

```sh
packet=research/work-items/RE-017-node115-positional-context-fixture
python3 -B "$packet/test_project.py"
python3 -B "$packet/project.py" checkpoint.rmp --sha256 CHECKPOINT_DIGEST --height H
python3 -B "$packet/project.py" checkpoint.rmp --sha256 CHECKPOINT_DIGEST --height H \
  --decoded-state decoded.bin --decoded-sha256 DECODED_DIGEST > staged.bin
```

The offline log records the pinned prior verifiers and the local runs with msgpack 1.1.2. It includes a genuine synthetic two-megabyte checkpoint stream and an assembled decoder-to-loader handoff. Full positional Context decoding, assigning native packed clock words, real archive provenance and H/H+1 root parity remain open.
