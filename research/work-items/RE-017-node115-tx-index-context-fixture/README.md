# RE-017 #115 transaction-index restore fixture

The [Context value reader](../RE-008-context-values-115/README.md) establishes the intermediate MessagePack option. This packet connects the option through named and positional Context completion to the first two qwords of the decoded state. It supplies those bytes to the [compact assembler](https://github.com/lalalune/hyperliquid-source/pull/7375) and then checks their transition through the [first replay stores](https://github.com/lalalune/hyperliquid-source/pull/7402).

- Named omission keeps the parser's unseen sentinel 2 at stack `+0x170`. At `0x30d3134..0x30d314d` this selects local defaults R15=1 and R14=0. Stores `0x30d3197/0x30d319a` install `(1,0)` at output `+0/+8`.
- An explicit `c0` token takes the nil route in `0x451c540`. It writes a zero tag with no meaningful payload. The fixture keeps the caller-supplied inactive payload bytes. An admitted integer writes tag one and the numeric word. The positional path calls the same reader at `0x30d3846` and copies its two words from its first staging lane to the same output region.
- For the selected integer tokens, the scalar reader at `0x14b7aa0` uses the nonnegative fixint path or dispatches unsigned and nonnegative signed widths through its table. Other forms are outside the supported token set.
- The compact materializer copies the first `0xba0` historical bytes unchanged. The first replay stage clears the tag while retaining the second word. Immediately before action initialization, the selected stage writes `(1,0)`.

```sh
packet=research/work-items/RE-017-node115-tx-index-context-fixture
python3 -B "$packet/verify.py"
python3 -B "$packet/test_project.py"
python3 -B "$packet/project.py" decoded.bin --sha256 DECODED_DIGEST --height H \
  --token-hex c0 > staged.bin
```

Use `--named-omitted` for a caller-established omitted field. This stages a single selected token and does not locate it in a complete checkpoint. The offline log records four fixture tests and checks four injected values across compact assembly and the first replay writes. Full Context decoding, real checkpoint and action execution, and H/H+1 root parity remain outside this proof.
