# RE-017 #115 startup hardfork rewrite and replay input

Component `abci`. On the selected local restore arm, a pre-rewrite copy of the two hardfork words lives at startup future +0x68/+0x70. The later replay spawn reads the two words from the materialized state's +0x18/+0x20. Keeping these addresses distinct determines which pair a checkpoint-to-replay fixture should supply after the optional startup rewrite.

## Static observations

- The materializer return is saved in future +0xe0 at `0x2cc19f4`. Before the freeze guard, `0x2cc1a29` and `0x2cc1a64` copy 16 bytes from state +0x18 to future +0x68. Neither freeze bypass edge runs the rewrite stores.
- The dword at state +0x10e8 must equal 1 to reach the unsigned freeze-height comparison. A target above state +0x28 takes the other bypass. A target below the current height branches to the failure helper and reaches `ud2` if that helper returns.
- At exact height, `0x2cc1c5e` reloads the pointer from future +0xe0. The code saturating-increments state +0x18 and replaces +0x20 with the word loaded from state +0x30. The pair at future +0x68/+0x70 is separate from the destination used by these writes.
- On the selected normal handoff, `0x2cc2bbd` loads future +0xe0. The tagged result carries it through future +0x20, and `0x2cc1651` loads it into R15. The empty-vector continuation reads state +0x18/+0x20 through R15 at `0x2cc24b2` and stages the pair at +0x100 of the spawn input. [The replay boundary packet](../RE-017-node115-local-restore-replay-pair/README.md) pins the task-frame copy and comparison loads at +0x100/+0x108.

## Consequence for offline fixtures

On the local MessagePack route, [the decoded values](https://github.com/lalalune/hyperliquid-source/pull/7255) make the two expectations `(hardfork.version, hardfork.round)` when bypassing the rewrite and `(hardfork.version.saturating_add(1), Context.round)` on the selected rewrite continuation. This inference assumes the intervening helpers return normally and no alias overwrites the state words before the read. It supplies a case where using the original future copy would produce a different second comparison word. The static result does not prove which branch a real checkpoint takes, a queue slot selection, a block application, or root equality.

## Offline verification

The verifier authenticates the pinned #115 ELF with SHA-256, checks selected instructions inside startup's FDE and recomputes branch targets and pair offsets. Run from the repo root:

```sh
python3 -B research/work-items/RE-017-node115-local-replay-hardfork-rewrite/verify.py
```

See the [raw offline output](offline-log.txt) and [instruction windows](windows.txt).
