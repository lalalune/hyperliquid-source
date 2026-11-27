# RE-009: node #115 same-owner expected-root provenance and H -> H+1 join

- Component ID: `storage` / `abci` (`qcp-expected-root-provenance`, issue #3923 / pilot #5391)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Method: static ELF/FDE/instruction/jump-table/census inspection over the authenticated #115 binary. No captured binary execution or emulation.
- Claim status: exact machine-code observations for the single-owner `0x5a04e40` replay path, the `H -> H+1` saturating increment, and the complete 27-site `.text` census of tracker offset `+0x3e50`; cryptographic internals, timer-delay configuration, alternate flat/wrapped timer paths, registry rotation, and live-chain trust authority remain explicitly open.

## Problem resolved

Prior evidence (`RE-017-node115-vote-to-replay-root-provenance`, #4114, #4157, #4117) connected the **live-engine** `0xdd` action handler (`0x294fdd0 -> 0x2760bc0 -> 0x28b2f10`) and the **slow/replay-engine** finalizer (`0x54897e0 -> 0x5afa030`) only conditionally, leaving three gaps blocking `qcp-expected-root-provenance` and `qcp-checkpoint-replay-root-fixture`:

1. Whether the replay consumer (`0x5a04e40`) passes the **exact same state instance** (`ctx + 0x450`) to both vote ingestion and finalizer drain.
2. Whether any **other writers** in the binary target `state + 0x3e50`.
3. How the restored checkpoint height `H` relates to `H + 1` and how local root production (`ctx + 0x400`) stays strictly separate from externally expected root provenance (`state + 0x3e50`).

## Findings

### 1. Single-owner join inside `0x5a04e40` (replay `apply_block`)

Within `0x5a04e40..0x5a065f8`, `r12` holds the replay context `ctx` and `*[ctx + 0x450]` holds its owned `Exchange` state pointer `S`:

- **Pre-execution admission (`0x5a04ebb..0x5a04f23`)**: loads `S = *[ctx + 0x450]`, checks `block.round > block.prev_round`, `[S + 0x30] == block.prev_round`, `[S + 0x18] == block+0x28`, and `[S + 0x20] == block+0x30`.
- **Single-pointer spill (`0x5a04f5f..0x5a04f67`)**: computes `&ctx.state = r12 + 0x450` and saves it to `[rsp + 0xe8]`.
- **Block actions on `&ctx.state` (`0x5a04fde..0x5a04fe9 -> 0x5483850`)**:
  - `0x5483867` dereferences `S = *[ctx + 0x450]` into `r13`.
  - **`H -> H + 1` height advance (`0x54838d3..0x54838e5`)**: reads `H = [S + 0x28]`, computes `H.saturating_add(1)` (`inc rsi; mov rdx, -1; cmovne rdx, rsi`), writes `H + 1` back to `[S + 0x28]`, and stores the block's new round at `[S + 0x30]`.
  - **Action execution (`0x5483e7a..0x5483e87 -> 0x5b30f30 -> 0x5863ab0 -> 0x54a3a00`)**: passes the identical `S` into the slow-engine action router `0x54a3a00`.
  - **Action tag `0xdd` (ABCI digest vote) dispatch (`0x54a3a6d..0x54a3a8a`, jump table `0x92688c[87] -> 0x54a430b`)**: calls `0x5548a80 -> 0x5869400` with `rcx = S`.
  - **Slow-engine vote handler (`0x5869400..0x586960e`)**: hashes the vote preimage (`0x38d2b00`), recovers the signer via slot `0x64e0ad8`, enforces recovered signer == sender and `vote_height < 0xccccccccccccccc`, forms **`S + 0x3e50`** at `0x5869511`, and calls `0x5afadd0 -> 0x537aa60`.
  - **Slow-engine selection latch & scheduling (`0x537aa60`, `0x5afadd0`)**: `0x537aa60` checks selector `[B + 0x20] == 0` (`0x537b28f`), evaluates the two-gate support predicate `0x5373810` (`0x36c7f70` weighted stake gate + `0x58c0aa0` count gate) before and after insertion (`0x537b2b0`, `0x537b370`), and on a false-to-true edge stores selector `0` at `[B + 0x20]` (`0x537b382`) and copies the 32-byte voted digest to `[B + 0x21..+0x40]` (`0x537b398..0x537b39d`). `0x5afadd0` then schedules the height in pending timer map `tracker + 0x60` via `0x4dbe1e0` (`0x5afb262`) and prunes heights below `height.saturating_sub(50000)` via `0x5376f80` (`0x5afb2ae`).
  - **Second slow-engine producer (`0x54cae80 -> 0x5afa3b0 -> 0x5373e40`)**: staking/validator mutations dispatched from the same `0x54a3a00` pass `S + 0x3e50` (`0x54cb062`) to `0x5afa3b0 -> 0x5373e40`, re-evaluating pending candidates and scheduling newly selected heights into `tracker + 0x60` (`0x5afa4cb`) and pruning via `0x5376f80` (`0x5afa50f`).
- **Finalizer drain on the identical `&ctx.state` (`0x5a055a8..0x5a055b0 -> 0x54897e0`)**:
  - `0x5a055a8` reloads the exact spilled pointer `[rsp + 0xe8]` (`&ctx.state = ctx + 0x450`).
  - `0x54897fb` dereferences the identical `S = *[ctx + 0x450]` into `r12`.
  - `0x548bf2d..0x548bf4b` passes `S + 0x3e50` to `0x5afa030`, which invokes pending-map timer processing `0x4de0540` on `tracker + 0x60` (with cutoff `saturating_sub(1000)` at `0x5afa04e`) and drains nonempty rows from `tracker + 0x48` into `result + 0x30`.
- **Replay comparison (`0x5a05c14..0x5a05e3c`)**: forwards the full batch to sink `ctx + 0x280` (`0x5a05c5e -> 0x4e3a020`), then looks up each row's height in local raw-root history `ctx + 0x400` (`0x5a05df6 -> 0x57f8bb0`) and compares the 32 bytes.
- **Local root production AFTER comparison (`0x5a05fc6..0x5a05fc9 -> 0x5a07ec0`)**:
  - `0x5a07ed7` reloads `S = *[ctx + 0x450]`.
  - `0x5a07ede` reads the incremented height **`H + 1`** from `[S + 0x28]`.
  - When root cadence triggers (`height % 10000 == 0`, hardfork height `[S + 0x10f0]`, or `height % [S + 0x39c8] == 0`), `0x5a07fce` computes the local state root via `0x548dad0` and `0x5a07fe5` inserts `(H + 1, local_root)` into `ctx + 0x400` via `0x5a03fa0`.

### 2. Strict separation of local vs. externally expected roots

Because `0x5a05df6` (comparison) executes **before** `0x5a05fc9` (`end_root_selector`), block `H + 1` writes `(H + 1, local_root(H + 1))` into `ctx + 0x400` at the end of block `H + 1`. An expected root for `H + 1` cannot come from that same block's local root calculation; it enters via external signed `0xdd` ABCI digest votes in subsequent blocks into `S + 0x3e50`, crosses both support gates, matures in `tracker + 0x60`, drains through `0x5afa030`, and is then compared against `ctx + 0x400[H + 1]`.

### 3. Complete `.text` census of tracker offset `+0x3e50`

Every occurrence of the 4-byte little-endian displacement `0x00003e50` in the entire 83,719,936-byte `.text` section is enumerated in `records.json` (**27 sites total, 0 unlisted**):

- 12 destructor calls (`0x2ac3a80`, `0x2ca6e30`, `0x2e02d90`, `0x3d14c80`, `0x5642360`, `0x5a57e10`; normal + unwind pairs)
- 9 copy/serde/root-capture sites (`0x3c2e860` checkpoint restore, `0x548ce30` snapshot clone, `0x55ea030` deserialize, `0x2c6bee0`/`0x2c6c800`/`0x5480950`/`0x55fcdf0` serialization, `0x269a1b0`/`0x4e34ce0` root capture)
- 1 read-only query (`0x2c71eb0 -> 0x2760030`)
- 2 live-engine producers (`0x294fdd0 -> 0x2760bc0 -> 0x28b2f10`; `0x2beecd0 -> 0x2760380`)
- 2 replay/slow-engine producers (`0x5869400 -> 0x5afadd0 -> 0x537aa60`; `0x54cae80 -> 0x5afa3b0 -> 0x5373e40`)
- 1 replay/slow-engine drain consumer (`0x54897e0 -> 0x5afa030`)

## Reproduce

```sh
python3 research/work-items/RE-009-node115-expected-root-provenance/verify.py --self-test
python3 -m unittest tests.test_expected_root_provenance_115
(cd research/work-items/RE-009-node115-expected-root-provenance && sha256sum -c MANIFEST.sha256)
```

## Unresolved boundaries

- Cryptographic preimage hash (`0x38d2b00`) and ECDSA signature recovery (`0x64e0ad8`) internals are treated as audited upstream boundaries, not re-proved here.
- Exact population of the timer-delay duration word (`tracker + 0x88`) and the alternate flat/wrapped timer path (`0x57f1690 -> 0x57d44d0`) remain open.
- Registry provenance/rotation at `S + 0x3f08` and full branch-by-branch parity of `0x537aa60` with `0x28b2f10` remain separate tasks.
- No live-chain root trust claim, captured binary execution, or full component acceptance gate (`mapped`/`built`/`behavior`/`identity`) is advanced by this packet alone.
