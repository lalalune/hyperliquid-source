# RE-017 #115 named JSON input to the local restore fixture

The [offline local restore fixture](https://github.com/lalalune/hyperliquid-source/pull/7338) expects decoded Context words and an optional scheduled freeze height. The [local JSON height and round analysis](https://github.com/lalalune/hyperliquid-source/pull/7261), [hardfork pair analysis](../RE-017-node115-local-json-hardfork-pair/README.md), and [freeze option analysis](https://github.com/lalalune/hyperliquid-source/pull/7263) identify the inputs in the named JSON form. This reader projects them together from a file with an independently supplied expected SHA-256 and requested height.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

| Selected field | Offline projection |
| --- | --- |
| `exchange.locus.ctx.height` | Required unsigned 64-bit height. The caller's requested height must match it. |
| `exchange.locus.ctx.round` | Optional unsigned 64-bit round with default zero. The alternate spelling `consensus_round` shares the same field and duplicate check. |
| `exchange.locus.ctx.hardfork` | Selected version and round pair. An omitted object gives two zero words. A supplied object in the supported form provides both unsigned values. |
| `exchange.scheduled_freeze_height` | Optional unsigned 64-bit height. An omitted field or JSON null yields an absent option, while zero remains present. A second occurrence still fails after null. |

The projector preserves each independent value and checks duplicate relevant fields before returning them. It does not apply the startup freeze decision. In particular, the Context's round stays separate from the saved hardfork round. The static verifier checks the alias, common unsigned visitor, defaults, option duplicate and output stores in the pinned ELF, and the existing hardfork packet separately verifies the older pair's decoder and handoff.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-json-restore-input/verify.py
python3 -B research/work-items/RE-017-node115-json-restore-input/test_projection.py
python3 -B research/work-items/RE-017-node115-json-restore-input/project.py \
  /path/to/local-capture.json --sha256 EXPECTED_FILE_SHA256 --height REQUESTED_HEIGHT
```

The tests include an actual temporary JSON file through the CLI, independent numeric fields, defaults, null and zero options, aliased duplicates, mismatched height, file identity and unsigned limits. The [offline log](offline-log.txt) contains the observed runs.

The reader loads a local named JSON file into memory and covers only these fields. MessagePack, other native forms, full checkpoint acceptance, producer identity and H/H+1 root parity remain outside this check.
