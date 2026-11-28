# RE-009 #115 checkpoint cadence word ingress

The existing [checkpoint cadence fixture](https://github.com/lalalune/hyperliquid-source/pull/7302) accepts a logical period, and the [paired root preflight](https://github.com/lalalune/hyperliquid-source/pull/7323) accepts explicit per-height gate inputs. This adapter stages the resolved native cadence from a named MessagePack checkpoint into the actual decoded state layout. The [compact assembler](https://github.com/lalalune/hyperliquid-source/pull/7375) then carries it to the root selector's input offset.

The [native cadence analysis](../RE-009-node115-checkpoint-root-cadence/README.md) binds required `exchange.msc`, with optional `aci`, to historical state `+0x1ea8`. An omitted or zero `aci` resolves to 1,000, and a positive value stays intact. The materializer copies the subobject at `+0x1de8` to compact `+0x3908`, carrying the resulting word to `+0x39c8`. The offline staging tool writes exactly eight bytes and checks independently pinned MessagePack and decoded fixture identities at the requested height.

```sh
packet=research/work-items/RE-009-node115-cadence-image-ingress
python3 -B "$packet/test_stage.py"
python3 -B "$packet/stage.py" checkpoint.rmp decoded.bin \
  --checkpoint-sha256 CHECKPOINT_DIGEST --decoded-sha256 DECODED_DIGEST --height H > staged.bin
```

The log includes native field verifiers, msgpack 1.1.2 tests and composition of two synthetic named source objects through compact assembly into the existing preflight. The root gate's mode and freeze availability remain independent. A reached writer gate does not establish that an actual archive row exists or that any state root matched.
