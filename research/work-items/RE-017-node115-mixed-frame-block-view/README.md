# RE-017: Select an unchanged Block view of a mixed #115 frame capture

The linked offline fixture accepts a Block-only capture. A mixed replay stream can contain a fully decoded opaque Tx before or between those Blocks. This adapter verifies the complete original stream and every raw frame and decoded payload against their supplied pins. It records the native decoded variant and physical coordinates of each frame, then builds a separately identified view from the unchanged raw Block frames in their original order. The existing frame and retained-link runner consumes that view. [Mixed payload selection](https://github.com/lalalune/hyperliquid-source/pull/7444) · [Block frame custody](https://github.com/lalalune/hyperliquid-source/pull/7662)

The synthetic source uses both plain and compressed framing, with three opaque Tx records at zero-based positions 0, 5 and 11. The original receipt still contains all 13 frames. The 10 Block frames have identical original-frame and decoded-payload hashes in the derived view, and pass all nine retained links and the selected synthetic H/H+1 Context checks. The controls independently reject wrong source-kind metadata and a Tx annotated with an observed prepared Block count. The Block view is an offline selection. Production capture direction, retained batch membership and checkpoint and reference provenance remain independently supplied inputs.

The verifier reads the pinned Linux x86-64 #115 ELF as data and reuses reconstructed Rust reader and decoder snapshots. Target SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95, and the exact local source snapshots listed in the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The supplied case follows the [framed capture manifest](https://github.com/lalalune/hyperliquid-source/pull/7662), with a `kind` entry of `Block` or `Tx` for each frame and `prepared_count` set to null for Tx. The source receipt records a Block-view index only for Block frames. The derived view's hash differs from the source mixed capture. See the [raw offline output](offline-log.txt).
