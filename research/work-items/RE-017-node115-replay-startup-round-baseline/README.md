# RE-017 · Node #115 initial replay receive-round baseline

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `cfeaee133b33ce9450a7434af19515b82171a8c6`. Addresses are linked ELF virtual addresses.

## Question

The replay Block consumer falls back to its future's +0x110 word when the receive buffer is empty. What do the two selected startup routes put there, and do they start with an empty receive buffer? This is a different input from the [joined startup expected pair](../RE-017-node115-replay-expected-pair-origin/README.md), the [local restore expected pair](../RE-017-node115-local-restore-replay-pair/README.md), and the [callback carried through +0x9a8](../RE-017-node115-replay-key-source/README.md).

## Observations

Let S be the materialized state pointer on the selected path and I the replay task constructor input at its call site.

| Startup route | Receive-buffer initialization | Baseline initialization |
| --- | --- | --- |
| Joined startup `0x2af45f0` | `0x2af57da..0x2af57ec` stage three qwords `(0, 8, 0)` on the stack. `0x2af5a7c..0x2af5a90` copy those words to the beginning of I at stack+0x640. | `0x2af5797` reloads the state pointer from the selected tag-2 startup result. `0x2af57a5` loads S+0x30 into R14, and `0x2af5a45` writes it to stack+0x750, or I+0x110. |
| Local restore `0x2cc1120` | `0x2cc24f0..0x2cc2508` stage the same three words. `0x2cc279b..0x2cc27b3` copy them to I at stack+0x7d0. | Following the previously pinned result, `0x2cc1651` loads the selected materialized state pointer into R15. `0x2cc24bc` takes S+0x30 into R12 and `0x2cc2763` writes it to stack+0x8e0, or I+0x110. |

The writes are raw copies. Neither startup route uses S+0x28 in the baseline transfer, nor increments the source word. Both calls resolve the same constructor at `0x5a81ed0`, which copies I's first 0x118 bytes to the beginning of its staging frame and preserves that prefix in the allocated future F. The constructor installs the poll whose relocation resolves to `0x5a82670`. Here `0x5a87613` reads the count and `0x5a87617` preloads the baseline. A zero count at this check keeps F+0x110 rather than reaching the tail-row load. The values above establish the field's initialization, conditional on the selected unwind-free normal paths and preserved state and frame contents before use.

The [checkpoint round packet](../RE-017-node115-checkpoint-round-source/README.md) identifies the selected MessagePack state+0x30 word as the decoded round and state+0x28 as the decoded height. On the separately established selected local field path, the resulting baseline is that round. The joined route's direct value source is its own S+0x30. This packet establishes no equality between the two state instances, nor a derived relation between height and round.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-startup-round-baseline/verify.py
```

The [offline run](offline-log.txt) records the target digest, exact check and observed results. The [selected instructions](windows.txt) identify the address and raw input bytes supporting the result. The verifier checks FDE coverage and constructor relocations, derives both input offsets and detects an altered instruction witness. Its synthetic cases use distinct height, round and hardfork words to check the projection and verify that an empty count does not select a tail word.

The binary is read as data. Actual checkpoint and received Block data, intervening concurrent updates, complete scheduler behavior and replayed state-root acceptance remain outside this result.
