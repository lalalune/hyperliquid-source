# RE-017 #115 local startup hardfork image rewrite

[The typed local startup fixture](https://github.com/lalalune/hyperliquid-source/pull/7338) exposes the original and replay comparison words. This packet adds a byte-level transition for the compact image, between [the local checkpoint input projection](https://github.com/lalalune/hyperliquid-source/pull/7580) and the downstream replay boundary.

The [native startup evidence](../RE-017-node115-local-replay-hardfork-rewrite/README.md) shows the original image pair at `+0x18/+0x20` copied to the startup future before the freeze guard. An absent option or an active target above the checkpoint height leaves the image unchanged at this boundary. A target below the current height takes the selected failure branch. At equality the code saturating-increments the version at `+0x18` and copies the independently persisted Context round from `+0x30` to `+0x20`. The [replay pair evidence](../RE-017-node115-local-restore-replay-pair/README.md) shows the later empty-vector handoff re-reading those materialized words into the replay comparison input.

The tool checks the `0x42c8`-byte compact image, its content digest, requested height, and ordinary freeze option. The input must be taken before the local startup rewrite. Run the transformer once for each such input. The report distinguishes the saved original pair from the resulting pair and includes the output digest. The optional binary output writes the resulting image. The only possible changes are within `+0x18..+0x28`.

```sh
packet=research/work-items/RE-017-node115-local-startup-image-rewrite
python3 -B "$packet/test_rewrite.py"
python3 -B "$packet/rewrite.py" compact.bin --sha256 PRE_REWRITE_DIGEST --height H
python3 -B "$packet/rewrite.py" compact.bin --sha256 PRE_REWRITE_DIGEST --height H --image > rewritten.bin
```

The log records both native verifiers, the focused tests and actual composition with the named MessagePack startup stager and independently compiled typed fixture. This is one local startup mutation before first replay. It does not recover a live checkpoint, execute a block or verify either state root.
