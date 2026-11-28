# RE-017 #115 pre-loader compact fixture assembly

The [composer](../RE-016-state-compose-434b9f0-115/README.md) and [materializer](../RE-016-state-materialize-3c2e860-115/README.md) packets describe consecutive layouts in the #115 restore path. The [LtHash lane comparator](https://github.com/lalalune/hyperliquid-source/pull/7366) expects an already-produced compact image. This assembler creates that image from a pinned decoded state value and a separately prepared EVM constructor block.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. A fixture must supply an exact `0x27a8`-byte decoded state value, the `0x1b20`-byte constructor block, and their expected file digests. Height is checked at decoded offset `+0x28`. The assembler applies the original tracked layout tables. It builds the intermediate `0x26d8`-byte composer result, then inserts it at compact offset `+0x1108`, producing exactly `0x42c8` bytes.

The native composer leaves four bytes at its tail untouched, which the materializer subsequently copies to compact offset `+0x37dc`. The materializer separately leaves three bytes beginning at `+0x42c5` untouched. The caller supplies these bytes explicitly for a deterministic fixture. Zeroes are usable synthetic fill when those positions are outside the check. They carry no claim about corresponding historical memory.

## Reproduce offline

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-compact-assemble-fixture/verify.py
python3 -B research/work-items/RE-017-node115-compact-assemble-fixture/test_assemble.py
python3 -B research/work-items/RE-017-node115-compact-assemble-fixture/assemble.py \
  decoded.bin evm-block.bin --decoded-sha256 PREDECODED_DIGEST \
  --evm-sha256 BLOCK_DIGEST --height H --composer-tail 00000000 \
  --compact-tail 000000 > compact-state.bin
```

The verifier authenticates native instructions and both pre-existing tables. The tests compare 48 complete synthetic outputs byte-for-byte with the two existing pure Python layout models, then check padding, rearrangement, input identities and a local consumer through the CLI. The tests call the pure models only. See the [offline log](offline-log.txt) for actual results.

This is a pre-loader byte image. It requires already decoded and prepared inputs. It does not decode an original checkpoint, prepare the EVM constructor block, execute startup writes, follow captured pointers, or verify an ABCI state root.
