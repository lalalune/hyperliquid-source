# RE-017 #115 EVM cache-hit constructor block fixture

The [compact-state assembler](https://github.com/lalalune/hyperliquid-source/pull/7375) requires a prepared `0x1b20`-byte constructor block. This fixture builds that block on the ordinary cache-hit path, between [#7337’s named sidecar projection](https://github.com/lalalune/hyperliquid-source/pull/7337) and the assembler. [#7366](https://github.com/lalalune/hyperliquid-source/pull/7366) provides the subsequent compact lane verification. The two binary input files carry explicit SHA-256 values.

The [native cache evidence](../RE-011-evm-db-checkpoint-hashes-115/README.md) maps the parser, cache-present decisions and constructors. The selected tag-1 constructors copy a descriptor of `0xf8` bytes followed by the `0x810`-byte record at option payload `+8`. At `0x38c28cd..0x38c2919` the return path joins the three `0x908`-byte regions in account, contract and storage order. Their block starts are `0x0`, `0x908` and `0x1210`. The store at `0x38c291c` places the original loader RSI word, saved in RBX, at block `+0x1b18` immediately after the three lanes. The subsequent return copy uses the entire `0x1b20` bytes.

The first input file contains the three concatenated `0x810`-byte raw records in the named sidecar projection's order. The second contains the three concatenated `0xf8`-byte descriptor regions in the same order, followed by the eight opaque tail bytes. The descriptor contents and tail remain explicit fixture inputs. The verifier checks their copy order and sizes without interpreting embedded pointer words or producing live DB descriptors.

From the repository root:

```sh
packet=research/work-items/RE-017-node115-evm-cache-block-fixture
python3 -B "$packet/verify.py"
python3 -B "$packet/test_block.py"
python3 -B "$packet/build_block.py" cache-records.bin descriptors-and-tail.bin \
  --records-sha256 RECORDS_DIGEST --descriptors-sha256 DESCRIPTORS_DIGEST \
  > evm-constructor-block.bin
```

The offline log verifies the digest-pinned native witnesses, exact fixture bytes and bad inputs. It also exercises the previous sidecar projector, assembler and lane comparator together, including a changed-lane negative control. The fixture models only the selected ordinary cache-hit return and leaves the fallback rebuild, runtime descriptor construction, live checkpoint provenance and state-root equivalence open.
