# RE-009 #115 named Locus scalar root comparison

Compare four scalar fields outside Context under native Exchange slot 0. Both the named RMP checkpoint and independent raw ABCI tree use SHA-256 pins. The raw tree must reproduce its declared digest. Its internal Context height leaf must also reproduce H before comparing the selected Locus fields.

| Path | Named value | Native preimage |
|---|---|---|
| `[0,5]` | `chn` | One byte. Local 0, Sandbox 1, Testnet 2, Mainnet 3. |
| `[0,6]` | `pdl` | One byte. False 0, true 1. |
| `[0,13,0]` | `hcm` | One little-endian qword inside the one-child branch at `[0,13]`. disabled 0, reduceOnly 1, enabled 2. |
| `[0,14]` | `pmu` | One unsigned little-endian qword. |

The selected named writers start from the shared Locus field captures. Writer `0x56763f0` selects `chn` literals by the byte tag using the relative table at `0x928bdc`. Writer `0x56764b0` picks the three `hcm` literals using zero, one and remaining branches. Writer `0x56783a0` emits the boolean marker, and `pmu` reaches the unsigned named writer from `0x5480d1b`. The raw visitors `0x141b650` and `0x1419d40` each append one byte. Visitor `0x44ebe70` writes a widened `hcm` tag into child 0. The `pmu` and internal Context-height visitors append one qword. Field meanings and startup control behavior are outside this parity comparison.

Use source pins and helper directory layouts from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) and [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344). The earlier [#6593](https://github.com/lalalune/hyperliquid-source/pull/6593) covers the named `pmu` reader. Run `python -B research/work-items/RE-009-node115-rmp-locus-scalars-root/verify.py --helpers PATH --rustc PATH` from the checkout root. The verifier reads the authenticated ELF and exercises 12 ordinary enum combinations, both booleans, maximum unsigned `pmu`, and a digest-valid raw reference whose inner Context height differs from its envelope. These are synthetic inputs.
