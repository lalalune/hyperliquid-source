# RE-009 #115 checkpoint root cadence source

The selected MessagePack checkpoint read carries `exchange.msc.aci` to decoded state `+0x1ea8` and then to materialized state `+0x39c8`. The selected root cadence step at `0x5a07f85` reads that word as the periodic divisor. This connects the historical checkpoint layout to the live field already identified by the [ExchangeMisc reader analysis](../RE-008-exchange-misc-readers-115/README.md).

- In the keyed Exchange visitor, table entry 58 selects `0x2fd8149`. Its duplicate name bytes spell `msc`. The normal child call at `0x2fd8164` enters the historical reader `0x31050e0`.
- The child arm at `0x3105b1d` uses duplicate name `aci` and stages the selected tag-9 word at `rsp+0x270`. Its initial value is zero. When the selected map finishes, the child chooses 1,000 if this word is zero, otherwise keeps the supplied value. It writes the chosen word at `rsp+0x398`, offset `+0xc0` into the `0xf8`-byte child result. This is the same selected default found earlier for the separate visitor in the [ExchangeMisc field packet](../RE-008-exchange-misc-offsets-115/README.md).
- The parent carries the word through the two `0xd0` transfers beginning at child output `+0x28` and writes it at historical Exchange `+0x1ea8`. The enclosing `0x2780`- and `0x27a8`-byte copies retain that coordinate.
- The [materializer](../RE-016-state-materialize-3c2e860-115/README.md) copies the historical `0xf8` bytes at `+0x1de8` to live `+0x3908`, which carries the cadence word to `+0x39c8`. The periodic branch reads it there.

The selected parent path requires the `msc` object. The zero default above is for the cadence field within that object. This copy proof relies on the selected normal returns, documented copy-slot binding, and no competing writes. It does not claim a real checkpoint's configured interval or a matched result root.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-root-cadence/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
