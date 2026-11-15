# RE-008: node #115 line framers in `0x25ebdb0..0x25f7350` and their writer names (stage 80)

- Component ID: abci. Question: the stage 79 census (RE-008-line-framer-census-115) found a block of line framers between `0x25ebdb0` and `0x25f7350` that call the line writer `0x14c37f0`, and tied none of them to a writer name. Which writers do they serve?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #5874 (writer names), #6033 / #6034 (abci log records), #6058 (catch-up step) and the stage 79 census. It imports only the merged `freeze_snapshot_115` helpers.
- Claim status: instruction bytes, call sites, FDE extents, string bytes and censuses are observations. "Framer", "wrapper", "writer", "record" and the names abci_hashes / abci_digest_quorum are labels inferred from those observations and from the cited packets. The binary was not executed.
- Scope included: the 30 framers in the block, their record serializer callee, their caller and its callers; byte-twin checks for the two bare framers, their serializers, the abci_hashes wrapper and the digest-step call window. Scope excluded: the writer arguments of the other 28 framers. Their callers are the block-and-transaction handler (`0x2e098e0`) and peer code (`0x2accee0`, `0x2ad0db0`, `0x2afa140`, …), which this packet does not enter.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/framer_writer_names_115.py --check
python3 -m unittest tests.test_framer_writer_names_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: census of the block

Every function whose FDE starts in `[0x25ebdb0, 0x25f7350)` and that calls `0x14c37f0` directly: 30. Of these, 28 call the time writer `0x2506050` (stage 79) and 2 do not. `evidence.json` lists, for each framer, the first record serializer it calls, its caller ("wrapper"), and the wrapper's callers.

Record serializers by framer count: `0x26a71c0` 11, `0x25f9bf0` 7, `0x27860c0` 2, `0x25fba40` 2, `0x2609fe0` 2, and one each for `0x2e13c40`, `0x25bd380`, `0x2e21c20`, `0x2e21840`, `0x28b5780`, `0x28b5950`.

## Evidence 2: the two bare framers are copies of the abci log framers

The tool compares each pair byte by byte. Every differing byte lies in a call rel32, a `call [rip+…]` slot displacement or a RIP-relative `lea`/`mov` displacement:
- slot displacements must reach the same slot;
- RIP `lea`/`mov` displacements must reach the same bytes (field names by their length);
- call displacements must reach two function starts with equal FDE lengths.

| Catch-up copy | Reference | Length | Differing fields | Reference role |
|---|---|---|---|---|
| `0x25f19b0` | `0x50e5fc0` | 0x184 | 11 | abci_hashes framer (#6034) |
| `0x25f4be0` | `0x50e6fe0` | 0x184 | 11 | abci_digest_quorum framer (#6033) |
| `0x28b5780` | `0x537d5e0` | 0x143 | 9 | abci_hashes record serializer |
| `0x28b5950` | `0x537d7b0` | 0x119 | 7 | abci_digest_quorum record serializer |
| `0x2d4ca40` | `0x4e3a7a0` | 0x1dd | 10 | abci_hashes line wrapper |
| `0x2bb38a6` | `0x548dbb6` | 0x48 | 3 | digest step call window |

The copy serializers load the same field names from a second copy of the strings: `0x28b5780` loads `height` (`0x5ff124`), `abci_digest` (`0x5ff768`) and `exchange_abci_hash` (`0x5ff773`); `0x28b5950` loads `height` and `d` (`0x5fec4d`).

## Evidence 3: who calls the two copies

- `0x25f19b0` is called from `0x2d4ca40`, which is called once, at `0x2bb38e9` in `0x2bb37c0`. That function is the catch-up step's own digest step (#6058). Its call window `0x2bb38a6..0x2bb38ee` is a copy of `0x548dbb6..0x548dbfe` in the layout-A digest step `0x548dad0`. The writer argument is `[rsp+0x18]` in both.
- `0x25f4be0` is called once, at `0x2d24b1a` in the catch-up wrapper `0x2d23610` (#6058).

Inference: the catch-up path writes the same abci_hashes and abci_digest_quorum lines as the main engine, through its own copies of the framers.

## Results and limitations

- Result: 30 framers in the block; 2 tied to writer names (abci_hashes, abci_digest_quorum); 28 untied.
- The 28 untied framers write a quoted time first. Their wrappers' callers are listed with the first string each loads:

  | Caller | First string loaded |
  |---|---|
  | `0x2accee0`, `0x2ad0db0` | `connection_checks…` |
  | `0x2ad5980`, `0x2ad6560` | `handle_stream_connection` |
  | `0x2afa140` | `consensus_rpc…` |
  | `0x2e098e0` | `Not sending heartbeat…` |
  | `0x2e157c0` | `committedblock hashes…` |
  | `0x2e1a120` | `add_tx…` |
  | `0x24240b0` | `Registering request…` |

  Following their writer arguments means reading peer and request-handling code. This packet stops there.
- The serializer column names a callee, not a full record layout.
- Twin call pairs are matched by equal FDE length, not by a full byte compare of each callee.
