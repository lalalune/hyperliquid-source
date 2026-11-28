# RE-017 feed a pinned #115 MessagePack checkpoint into the paired-root fixture

The paired-root verifier runs the reconstructed Rust engine at H and H+1. Its original entry consumes a text fixture with manually supplied restore values. This adapter derives the restore coordinates and controls from the same original MessagePack checkpoint. It takes the height and restored round from positional Context slots 2 and 4, the ordered hardfork version and round from the child at slot 1, and the configured cadence from `exchange.msc.aci`. A zero or omitted `aci` inside the present map projects to 1,000 on the selected restore path. The loader count and one auxiliary digest remain explicit fixture inputs. [Paired engine roots](https://github.com/lalalune/hyperliquid-source/pull/7788) · [Positional Context](https://github.com/lalalune/hyperliquid-source/pull/7536) · [Cadence source](https://github.com/lalalune/hyperliquid-source/pull/7267)

The synthetic case supplies a checkpoint at H=42 and round 40. The reconstructed engine decodes the original pinned Block, checks the checkpoint's hardfork pair [5, 40] and computes both roots at the actual heights. The two independent raw reference rows match. Changing only the valid H+1 reference leaves H matching and H+1 different. Changing the checkpoint height stops before the engine runs. Changing the stored hardfork round to 39 triggers the engine probe's checkpoint/Block operand check. The separate cadence control exercises the zero-to-1,000 projection.

The verifier rechecks the selected positional, hardfork, cadence and engine anchors against the Linux x86-64 #115 artifact with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The paired engine captures only two Context leaves and one independently supplied auxiliary leaf in a synthetic state. Production snapshot materialization, the other capture slots and production state-root parity remain open.

## Reproduce

Use Python with msgpack 1.1.2 and BLAKE3 1.0.11, Rust 1.95, and the exact dependency commits recorded in `verify.py`. From the repository root set `packet` to this directory.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The case declares `height`, `checkpoint_rmp`, `wire`, `reference_h`, `reference_h_plus_one`, and `fixture_inputs`. The artifact entries accept `path` and `sha256`. The fixture inputs supply an unsigned `persisted_loader_count` and a 64-digit lowercase `auxiliary_digest`. The checkpoint uses a named Exchange/Locus envelope with a positional Context and a named hardfork child and cadence map. The reconstructed fixture still requires H and H+1 to qualify for root capture. [Raw offline output](offline-log.txt)
