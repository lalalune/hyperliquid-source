# RE-017 emit native compact #115 order results in replica Full JSON

The structured success dispatcher selects the compact order writer at `0x5086350`. That path calls the `statuses` array writer through `0x518a360`. The array iterates 48-byte rows and uses the five-way element table at `0x91d23c`. This adds the order arm to the existing typed replica Full writer. [Success dispatcher](../RE-017-node115-replica-success-dispatch/README.md) · [Existing typed Full emitter](https://github.com/lalalune/hyperliquid-source/pull/7530) · [Separate MessagePack response fingerprint](https://github.com/lalalune/hyperliquid-source/pull/7803)

The filled branch writes `totalSz`, `avgPx`, `oid` and optional `cloid` in order. Resting writes `oid` followed by the optional `cloid`. The quantities pass through the selected native normalization helper and then the quoted JSON writer. The fixture accepts already normalized text. Order IDs are unsigned decimal, and a present cloid emits all 16 bytes in lowercase prefixed hexadecimal. The waiting branches write their names as strings. The error branch writes a one-key object through the existing JSON escaper. Empty order arrays retain the `data.statuses` wrapper.

The verifier authenticates node #115 Linux x86-64 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, validates selected instruction ranges and the name, table and relocation references, and compiles the reconstructed Rust module with the exact #7530 emitter snapshot in temporary storage. The full-response fixture checks all five statuses in original order with both cloid presence cases, a maximum unsigned order ID, and a UTF-8 nested error that needs escaping. The previous typed and generic tests also pass. Native float rendering, writing actual orders and production state-root parity remain separate.

## Reproduce

From the repository root, set `packet` to this directory. Use Rust 1.95 and the exact #7530 commit recorded by the verifier.

```sh
python3 -B -u "$packet/verify.py"
```

The [raw offline output](offline-log.txt) includes both the static checks and the Rust test run.
