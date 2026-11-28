# RE-017 #115 expected replay pair from local-state restore

On the selected successful local-state path, the replay Block gate compares against two words from the materialized state returned to `0x2cc1120`. This links the [local restore result](../RE-017-local-state-restore-115/README.md) to the expected side of [the replay Block gate](https://github.com/lalalune/hyperliquid-source/pull/7247). The [joined startup lane](https://github.com/lalalune/hyperliquid-source/pull/7248) reaches the same spawn API through a different producer.

| Boundary | Selected path |
| --- | --- |
| Restore return | The local reader succeeds and its decoded input reaches builder `0x3c13610` through the call at `0x2cc19ea`. The caller saves the returned address at future+0xe0. |
| Tag and pointer | `0x2cc2bbd` reloads this address. The continuation at `0x2cc1295` writes tag `0x8000000000000001` and pointer to future+0x18/+0x20. The classifier routes this tag through `0x2cc151a` to `0x2cc1649`, where `0x2cc1651` puts the pointer in R15. |
| Empty-vector continuation | With the context mode enabled and state+0xb9a equal to context+0x5a, the branch at `0x2cc16b9` enters `0x2cc180e`. Either the selected sentinel at state+0x38e0 or zero at state+0x38f0 takes the empty-vector branch to `0x2cc22cc`. Under normal helper returns this route preserves R15 into `0x2cc24b2`. |
| Compare input | `0x2cc24b2` reads state+0x18/+0x20. The pair passes through stack+0x10 to stack+0x8d0, which is +0x100 relative to the spawn input at stack+0x7d0. The constructor copies the pair into its task frame, whose poll reads +0x100/+0x108 in order. |

The intermediate calculation at `0x2cc21a1` is on a different dispatch. Its first table entry goes through the nested call at `0x2cc6356`, whose selected result replaces R15 at `0x2cc638a`. That intermediate inline pointer alone gives no provenance for the late pair read.

The evidence applies to the selected locally restored state and assumes normal helper returns and no intervening alias writes. It supplies the same-object field projection needed for a replay fixture. The values of those fields in an actual checkpoint, their relation to H or H+1, and an end-to-end root match remain open.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-local-restore-replay-pair/verify.py
```

The verifier checks the pinned ELF, FDE boundaries, selected pointer and pair offsets, conditional targets, constructor relocations and the separate inline dispatch. See [raw output](offline-log.txt) and [selected instructions](windows.txt).
