# RE-009 · Compare three Exchange Time leaves from a #115 checkpoint and raw export

The offline checker converts three ordinary named Exchange checkpoint clocks into the 12-byte input consumed by each raw ABCI leaf. It pins both inputs, checks the checkpoint's decoded Context height and the raw export height, and recalculates the complete raw export digest. It then compares the three leaf digests and reports differences by name.

| Checkpoint field | Exchange offset | Raw slot | Named writer call |
| --- | --- | --- | --- |
| `last_hlp_cancel_time` | `+0x4288` | 15 | `0x5481020` |
| `post_only_until_time` | `+0x4294` | 16 | `0x548104b` |
| `lvt` | `+0x42a0` | 45 | `0x5481479` |

These clocks use the same canonical text renderer and raw leaf encoder as the earlier Context comparison at `[0,0]`. A leaf preimage contains eight little-endian signed Unix seconds bytes followed by four little-endian nanosecond bytes. The supplied fixture shape uses ordinary four-digit years, seconds 0–59 and canonical 0/3/6/9 fractional digits. Extended years and leap seconds require separate handling. A missing key or a noncanonical value cannot be used as evidence of equality.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The three names and compact field addresses all enter `0x5676bd0`. It supplies the four-byte literal `Time` and jumps to `0x52fd6d0`. The ordinary path calls `0x5307510`, the same renderer used by Context's `0x4e0da40`. The rendered `T`-joined clock goes to named MessagePack string writer `0x57cf860`.
- The three raw slots share descriptor `0x64a8368` and visitor `0x3d5e950`. The veneer jumps through relocation `0x64df5a0` to `0x141b1e0`. The visitor derives seconds from the packed date and time, appends the eight-byte result, then appends the four-byte source nanosecond word.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps the Exchange names to slots. [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) covers ordinary clocks inside Context. This packet joins the writer and raw paths for all three standalone Exchange clock fields.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the exact named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), the clock normalizer from [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368), the leaf preimage encoder from [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) and the ordered export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under one helper directory. File paths and expected SHAs are in `compare_times.py` and `verify.py`.

```sh
python3 -B research/work-items/RE-009-node115-rmp-exchange-times/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` driver, run `compare_times.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline run](offline-log.txt) checks pre-epoch and leap-day times, all four supported fractional widths, a one-nanosecond `lvt` difference, malformed spelling, height mismatch and an inconsistent reference digest. The inputs are synthetic. Establishing actual chain parity requires a genuine same-height checkpoint and raw export.
