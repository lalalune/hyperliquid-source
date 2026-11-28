# RE-017 #115 local JSON hardfork pair into the startup state

Component `abci`. The selected local JSON restore path preserves the pair from [the Locus staging slots](https://github.com/lalalune/hyperliquid-source/pull/7259) into the materialized startup state at +0x18/+0x20. This extends the JSON evidence to the same startup boundary already documented for [local MessagePack](../RE-017-node115-local-hardfork-materialization/README.md).

| Boundary | Observed pair transfer |
| --- | --- |
| Locus | Stack +0x2c8/+0x2d0 move to +0x1778/+0x1780 through two SIMD loads. The selected `0xba0`-byte copies start at +0x1760 and preserve the pair through +0x2490 and +0x338. The suffix copy from +0x348 to +0x3218 and then output+0x10 retains both displacements. |
| Exchange | The Locus return starts at stack+0xc20. Its suffix moves from +0xc30 into +0x6af0. The selected aggregate copies preserve the pair at +0x18/+0x20 through bases +0x6ae0, +0xc20, +0x3488, and +0x7680. The final suffix copy from +0xc30 via +0xa9d0 writes output+0x10 onward. |
| JSON allocation | At `0x1f3da2a`, the selected non-null allocation receives 0x27a8 bytes from the Exchange child result. Its pointer reaches RDX at `0x1f3dbe6`. On the successful suffix check in `0x1d74270`, the wrapper returns it through the file reader. |
| Materialization | The caller preserves the pointer in R15 and passes it at `0x2cc19ea`. The resolved materializer copies the leading 0xba0 bytes at `0x3c2f00a`. The allocation copy at `0x3c13689` carries both words to the materialized offsets, before the optional rewrite. |

This result assumes selected normal helper returns, ordinary copy semantics, and no intervening alias writes. It identifies the initial hardfork values for the selected JSON decode lane. It leaves JSON freeze-field provenance, exact checkpoint data and root equality outside the contribution.

## Offline verification

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-json-hardfork-materialize/verify.py
```

The verifier reads the ELF as data. [Raw output](offline-log.txt) records the pinned digest and the results of the byte, FDE, operand and relocation checks against the [instruction windows](windows.txt).
