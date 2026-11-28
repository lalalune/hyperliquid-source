# RE-017 #115 named MessagePack local startup fields

This adapter stages the local checkpoint's original hardfork and scheduled freeze fields into a caller-pinned decoded fixture. The [named JSON fixture](https://github.com/lalalune/hyperliquid-source/pull/7364) projects values without writing decoded fixture bytes. The [positional Context projector](https://github.com/lalalune/hyperliquid-source/pull/7536) covers a different Context shape and stages the independent round word. The [Rust compact ingress](https://github.com/lalalune/hyperliquid-source/pull/7561) consumes the bytes after assembly.

The [local Context analysis](../RE-017-node115-local-context-hardfork/README.md) and [materialization analysis](../RE-017-node115-local-hardfork-materialization/README.md) show that `exchange.locus.ctx.hardfork.version/round` become decoded `+0x18/+0x20`. Omitting the whole object yields two zero words. A present object must supply both words in the selected map shape. The [freeze option analysis](../RE-017-node115-local-scheduled-freeze-option/README.md) maps `exchange.scheduled_freeze_height` to the qword tag and payload at `+0x10e8/+0x10f0`. Missing or nil stages tag zero and leaves the inactive payload as supplied by the fixture. An unsigned value stages tag one and the payload, including an explicit zero.

The parser checks one digest-pinned local MessagePack object, named map shapes, selected duplicate fields and requested height. Staging independently checks the decoded image's digest, size and height. The saved Context round already in that decoded image remains independent of the newly staged hardfork round.

```sh
packet=research/work-items/RE-017-node115-named-rmp-startup-staging
python3 -B "$packet/test_stage.py"
python3 -B "$packet/stage.py" checkpoint.rmp --sha256 CHECKPOINT_DIGEST --height H \
  --decoded-state decoded.bin --decoded-sha256 DECODED_DIGEST > staged.bin
```

The offline log includes the pinned static verifiers, local msgpack 1.1.2 tests and an end-to-end composition of named files with the compact assembler and Rust local restore fixture. Real checkpoint acquisition, full object acceptance, replay execution and root parity remain outside this selected projection.
