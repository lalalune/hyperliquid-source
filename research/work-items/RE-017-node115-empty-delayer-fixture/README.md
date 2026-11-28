# RE-017 #115 empty action-delayer loader fixture

This fixture materializes the ordinary-empty action-delayer update between the selected post-c-staking and post-action-delayer direct stores in [#7390](https://github.com/lalalune/hyperliquid-source/pull/7390). The prior [#5057](https://github.com/lalalune/hyperliquid-source/pull/5057) packet established the static path. The new artifact is a digest- and height-pinned local fixture transformer with byte comparisons and unsupported-path controls. The loader sites and target instructions are read from the pinned #115 ELF only.

The caller forms `state + 0x40c0` at `0x3c1294b` and dispatches via slot `0x64e4f10` to `0x3bec320`. Take the ordinary branch where the first qword differs from the sentinel and both the ring count at subobject `+0x18` and destination word at `+0x20` are zero. The two selected empty helper routes perform no object mutation or row dereference. The initializer stages qwords `(0, 8, 0, 0)` and writes them to compact offsets `0x40e0..0x4100`, then writes a zero qword at `0x4120`. See `0x3bec97c..0x3bec991` for the sources and `0x3beccb6..0x3becccd` for the stores. The latter runs without a destination deallocation under the stated preconditions.

From the repository root:

```sh
packet=research/work-items/RE-017-node115-empty-delayer-fixture
python3 -B "$packet/verify.py"
python3 -B "$packet/test_project.py"
python3 -B "$packet/project.py" fixture.bin --sha256 EXPECTED_DIGEST --height H > after-delayer.bin
```

The input is an explicit local compact fixture of `0x42c8` bytes from immediately before the helper at height `H`. The expected digest identifies those bytes. Output can feed the already-established post-action-delayer direct stores. The fixture preserves every unrelated byte. It rejects the sentinel, nonempty and nonzero destination cases. It neither resolves native object pointers nor establishes the contents of a real checkpoint, the later replay extractor's effects, or root parity. No node instruction execution, emulation, external service, or gate movement is required.
