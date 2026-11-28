# RE-009: Stream height and round from a named checkpoint

An offline replay needs the checkpoint's persisted height and round as
distinct inputs. This reader extracts `exchange.locus.ctx.height` and
`round` or `consensus_round` from a pinned decompressed MessagePack file.
It streams past unrelated values so that testing the coordinate pair does
not first require a fully materialized exchange state.

The [selected decoder proof](../RE-017-node115-checkpoint-round-source/README.md)
binds the height and round to separate output words, aliases the two
round spellings and supplies zero when the selected round field is absent.
The verifier authenticates those instruction anchors and owning FDEs.
The reader retains whether the selected round value came from a field.
It rejects a missing height, conflicting aliases and extra bytes after
the single outer object.

The tests are synthetic and include a large unrelated array, distinct
height and round, absent and explicit zero and file identity controls.
This reader handles the selected named-map format. It does not restore
the remaining state fields or establish a real checkpoint's origin.

With Python 3.11 or later and optional `msgpack==1.1.2` available:

```sh
packet=research/work-items/RE-009-node115-checkpoint-coordinate-stream
python3 -B "$packet/verify.py"
python3 -B -m unittest discover -v -s "$packet" -p test_coordinates.py
python3 -B "$packet/read_coordinates.py" checkpoint.rmp --sha256 "$checkpoint_sha"
```

[Raw offline output](offline-log.txt)
