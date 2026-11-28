# RE-017 #115 local JSON scheduled freeze height

Component `abci`. On the selected local JSON Exchange map path, omitting `scheduled_freeze_height` or setting it to JSON `null` returns an absent option. A successfully decoded unsigned height returns a present option whose payload the startup guard can compare with the restored height.

- The local JSON Exchange visitor at `0x1d7f620` dispatches index 13 to `0x1d80844`. It initializes stack+0xa8 to unseen tag 2. The duplicate arm references the exact 23-byte field name.
- The selected arm calls `0x22a76d0`. Its `null` path checks all four characters and stores tag 0. The scalar path uses `0x1d772e0`, advances the scalar result tag and stores its payload at output+8. On the successful scalar arm the option tag is 1. Returned tag 2 takes the map error path.
- The selected successful completion maps an unseen tag 2 to zero. Observed tags 0 and 1 are preserved. Stores at `0x1d909d6` and `0x1d909e6` emit the tag and payload at Exchange +0x10e8 and +0x10f0. Only the tag-1 payload has a height meaning.
- The JSON outer copies preserve both offsets and the shared materializer copies the 16-byte option lane into the startup state. [The startup guard](../RE-017-node115-local-replay-hardfork-rewrite/README.md) tests the low dword of the first word, then compares the second word when the tag equals 1.

The packet pins JSON object inputs for the rewrite and bypass branches alongside the [MessagePack option evidence](../RE-017-node115-local-scheduled-freeze-option/README.md). Its scope covers selected successful branches and ordinary copy semantics. It does not fix an actual checkpoint's freeze height, establish queue admission or compare roots.

## Offline verification

From the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-json-freeze-option/verify.py
```

The verifier authenticates the capture and checks the selected field table, diagnostics, option return instructions, copy operands and startup reads. See [raw output](offline-log.txt) and [instruction windows](windows.txt).
