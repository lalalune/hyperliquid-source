# RE-010 · Node #115 batchModify row bounds and scan

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

A deterministic replay needs the row stride and error precedence for `batchModify`. This packet checks the selected decoder call `0x4d40bc0 → 0x5717bf0` and its successful internal tag `0x88`. The selected execute cell reaches wrapper `0x54ff1a0` via call site `0x54a3463` with Action offset 8 as the payload pointer.

Both examined routes in this wrapper load a count from payload offset `+0x10`. At 10,001 or above, they converge on `0x54ff5b0`, which stages result word `0x158` before the preparation call. Below that bound, the pointer at `+0x08` becomes the range beginning and the wrapper computes `end = begin + 80 * count`. The multiplication is a left shift by four followed by scaling by five.

The forward scan checks the byte at row offset `+0x4e` and advances by `0x50` bytes on the nonzero path. A zero-sized range goes directly to range preparation. A zero flag leads to a lookup only if state member `+0x16e8` is present; the business meaning of the flag is unresolved.

The preparation call at `0x54ff7e0` targets `0x50fa240`. After preparation and both checks return word `0x1a2`, call site `0x54ff8ad` passes the original payload to `0x5132ab0`. The observed bound and stride apply at admission. This packet does not establish per-row execution effects, error names or whether results are committed atomically.

Run `python3 research/work-items/RE-010-node115-batch-modify-rows/verify.py` from the repository root. It rechecks cells, instructions and relative edges on the authenticated ELF and rejects mutations of the count bound, flag offset and downstream target.
