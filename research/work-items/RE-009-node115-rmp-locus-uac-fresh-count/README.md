# Derive the Locus uac count at fresh named restore

The raw ABCI Locus `uac` visitor reads its count from the occupied table word at `+0x30`. The named serialization enumerates dense rows through `+0x10`. PR #7801 keeps the two inputs separate so a raw reference comparison can consume an independently pinned count. This companion derives a count witness directly from a narrow fresh named checkpoint restore, which makes that comparison possible when the selected checkpoint is supplied but the compact capture is absent.

## Native evidence

The named Locus reader's `uac` arm calls `0x3292600` at `0x332caaf`. Its selected contiguous reader passes an input span into `0x47027b0` at `0x3292b48`. That function reserves the lesser of the span byte length and `0x1249` dense rows, then asks `0x3ee6130` to construct the associated table. The table constructor zeroes its occupied count at `0x3ee624d`. At `0x4702848..0x4702850` that count becomes working-object `+0x30`. When the span is empty, the all-zero constant at `0x648f9d8` initializes the same word. Both paths explicitly zero the dense length at `0x4702864` or `0x47028b4`.

The selected reader passes that same working object to `0x47154f0` at `0x470299e`. Its ordinary new-row call at `0x4715665` reaches `0x3ecb420`. This writes the incremented table count at `0x3ecb5ed` and incremented dense length at `0x3ecb74c` before returning the zero status at `0x3ecb75e`. The reader loops on that status and builds its duplicate-key error on the other path. Successful completion copies both count fields into the returned compact object at `0x4702a50` and `0x4702a58`.

`derive_uac_count.py` supports complete named inputs up to 4,681 rows. Each recognized row consumes at least one byte of the named payload, so that conservative limit fits the selected initial reservation. It reuses the pinned named projection from #7801 and requires all rows to decode with unique normalized Address keys. The tool emits the same checkpoint-byte and height-bound witness shape used by the raw comparator. Existing compact captures and later replay-mutated state still require their own supplied count.

## Reproduce

From the checkout root with Python and msgpack 1.1.2, provide the directory containing the pinned prior helpers and a Rust compiler. The verifier reads the artifact statically and compiles only the repository's BLAKE3 fixture driver. It derives count witnesses for zero and one rows, compares each with separately assembled synthetic raw trees, changes just the reference count, and checks the reservation limit, duplicate normalized Address, wrong height, and wrong checkpoint pin.

```sh
python -B verify.py --helpers /path/to/pinned/helpers --rustc /path/to/rustc
python -B derive_uac_count.py /path/to/pinned/helpers HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256
```

`offline-log.txt` records the actual verification. The fixtures establish the selected count bridge. They leave real checkpoint and first replay raw root parity open.
