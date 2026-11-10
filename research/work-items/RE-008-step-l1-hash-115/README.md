# RE-008: node #115 l1 hash inside the abci steps (58th stage)

- Component ID: abci. Question: stage 57 (open PR #6039) found `l1 = BLAKE3(BLAKE3(bytes) || digest32)` in `0x457cf60`, reached only through the blocking helper `0x452aab0` from seven call sites. It traced the hardfork_hashes worker site. This stage answers what the two step sites pass as `bytes`, when they compute the hash, and where the result goes. It also names the other four call sites as far as static strings allow.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6038 and #6039; uses only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, offsets, relocations, strings, FDE extents and direct-call censuses are observations. "freeze/periodic snapshot", "serialised abci state", "l1 map", "digest map" and "networking boundary" are inferred labels from strings and earlier packets. The binary was not executed.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/step_l1_hash_115.py --check
python3 -m unittest tests.test_step_l1_hash_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: when the steps compute the l1 hash

Layout-A step `0x5a07ec0` (layout B `0x5a08720` has the same shape):

- `0x5a07f80` `test bpl, bpl` / `jne` and `0x5a07f85` `mov rcx, [rsi+0x39c8]`: the digest step `0x548dad0` runs when `bpl` is set or the height divides by box `+0x39c8` (B: `0x548d8c0`, box `+0x4538`, #6023).
- `0x5a07fea` `test bpl, bpl` / `0x5a07fed` `je 0x5a08351` (B: `0x5a0884d`): everything below, including the l1 hash, runs only when `bpl` is set.
- `0x5a08011` `test r13b, r13b` / `cmovne rdx, rax` and `lea rcx, [rax*2+6]`: the label is `freeze` (6 bytes, `0x93a687`) when `r13b` is set, else `periodic` (8 bytes, `0x458f30`), as in #5925 and #5999.

## Evidence 2: the bytes are the serialised abci state

- The A step calls `0x5485a60` (its only direct call, `0x5a0801e`) with the label. B calls `0x5485f80` (#5999).
- `0x5485a60` loads `&str` slot `0x64aa220` (relocated to `0x929ae3`, `abci_state`) for the `hyperliquid_data` path builder `0x5942870` (#6001). It runs `0x4e49960` with `edx = 1` → `0x4e35e90` → closure `0x4e4af80`, which calls `0x5480950` with config `0x01000400`. The B closure `0x4e4b3f0` calls `0x5481900` with the same config (#6002).
- `0x5485a60` copies the 0x38-byte result of `0x4e49960` to its output unchanged (`0x5485d82` → `[r15+0x8]`, and so on).
- The step builds the l1 record `{ret+0x8 (ptr), ret+0x10 (len), &rsp+0x80 (the digest from the digest step's output at rsp+0x130), &rsp+0x40 (height r15)}` and calls `0x452aab0` with `edx = 1` (`0x5a080b9`; B `0x5a08919`).

## Evidence 3: where the l1 hash goes

- Both steps call `0x5a046f0(engine value +0x3e0, height, &l1)` (`0x5a08267`, `0x5a08ac7`). These are its only two direct calls.
- `0x5a046f0` has the same entry shape as the digest-map insert `0x5a03fa0` (#6023) and also trims at `0x33` entries (`cmp rdx, 0x33` at `0x5a04711` and `0x5a03fc1`). `0x5a03fa0`'s only two direct calls are the steps' digest inserts on engine value `+0x400`.
- Inference: the steps keep a second (height, l1) map next to the (height, digest) map, with the same 51-entry bound.
- The step also fills a local 0x80-byte record at `rsp+0xa8` in the same layout as the hardfork_hashes worker's output (#6038): serialised state, height at `+0x38`, l1 at `+0x40`, digest at `+0x60`. Its later use is not traced.

## Evidence 4: the other four call sites

| Site | Function | Evidence loaded in the function | Stopped |
|---|---|---|---|
| `0x2ad8dc1` | `0x2ad7140` | `node/src/gossip_config.rs` (`0x449029`) | networking boundary |
| `0x2cae5c8` | `0x2cad9b0` | `node/src/gossip_config.rs` | networking boundary |
| `0x2d26391` | `0x2d25620` | the freeze-height assertion (`0x5eadd9`) | not traced |
| `0x5a6812a` | `0x5a64aa0` | `node/src/gossip_config.rs` | networking boundary |

`0x2d25620` also loads `freeze` and `periodic` near its call, so it is a third step-like caller; it is not traced here.

## Implementation and comparison

The tool pins 38 instruction byte runs, 21 rel32/RIP references, 4 strings, one relocation, three enclosing FDEs and two direct-call censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: on a snapshot block (the `bpl` path), each step serialises the abci state, hashes it with the stage-57 l1 formula bound to the freshly computed digest, and inserts (height, l1) into a 51-entry map at engine value `+0x3e0`.
- Limits: readers of the `+0x3e0` map; the later use of the local 0x80-byte record; whether the four step sites share one serialiser format (A and B use different serialisers with the same config); the step-like caller `0x2d25620`; anything past the gossip boundary. No gate changes.
