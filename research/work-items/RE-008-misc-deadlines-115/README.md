# RE-008: node #115 ExchangeMisc pmc update in begin_block A and the tce range check (stage 94)

- Component ID: abci. Question: open PR #6103 found that begin_block A `0x54b66b0` resets ExchangeMisc `pmc` (box `+0x39f0`) and, when it is set, adds 600.0 s to it, and that the `tce` handler checks a value against 5..=10080. It left open where the 600 s deadline is compared, when `pmc` is written, and what the checked value feeds.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6103 and uses the time helpers bound in #5861. It imports only the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, constants, relocations and the range model are observations. "Candidate time", "cursor", "deadline", "Locus cls" and "error tag" are inferred labels. The binary was not executed.
- Scope included: begin_block A from `0x54b8b86` to `0x54c02bc` (pmc paths) and the start of handler `0x57c9f60`. Scope excluded: the cursor loop body (`0x54bffb9`..`0x54c0188`), what box `+0x4270` and `+0x710` hold, the handler after `0x57ca020`, begin_block B, and the `mtpt` consumer `0x5a1e320`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/misc_deadlines_115.py --check
python3 -m unittest tests.test_misc_deadlines_115
```

The tool reads the ELF. It does not execute the binary and does not start objdump or readelf. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: the pmc candidate and reset

- `0x54b8b86`..`0x54b8b9f`: a 12-byte date-time is read from `[[rsp+0x2e8]+0x8]` into `rsp+0x1b8`; `0x54bfdd7`..`0x54bfded` copy it to `rsp+0x430`.
- `0x54bfdf5`/`0x54bfdff`: when box `+0x4270` is 0 or box `+0x710` is 0, `0x54bfe3c`/`0x54bfe47` store the unset value (`0xf6401a`, 0) to `pmc` and leave this part.

## Evidence 2: a 20-byte cursor

- `0x54bfe10`: `r14 = box+0x42b1`. When box `+0x42b0` is 1 at entry, its 20 bytes are saved at `rsp+0x310` (`0x54bfe31`); otherwise the saved copy is zeroed.
- Inside the loop, `0x54c008f` sets box `+0x42b0 = 1` and `0x54c009d` writes the cursor bytes.

## Evidence 3: the 600 s deadline is computed and dropped

- `0x54c018d`..`0x54c01ab`: `pmc` is loaded and compared with the unset value; unset skips to `0x54c0274`.
- Set: `0x54c01c6` loads 600.0 (`0x459568`) and calls the #5861 helpers through slots `0x64e0f70` (`0x15ed960`), `0x64e0f78` (`0x162a9a0`) and `0x64e0aa0` (`0x16290d0`).
- The date-add result is returned in `eax` and is not stored: `0x54c0274` overwrites `rax`. In this build the deadline has no effect.

## Evidence 4: the conditional pmc store

- `0x54c0279`: when box `+0x42b0` bit 0 is set, `memcmp(box+0x42b1, rsp+0x310, 20)` (GLOB_DAT `0x64dfb50`) runs.
- `0x54c029a` `jg` skips the store; otherwise `0x54c02ae`/`0x54c02b9` write the candidate from `rsp+0x430` to `pmc`.
- Inference: `pmc` records the time at which the cursor stopped moving forward (wrapped or stayed), once per pass.

## Evidence 5: the tce handler range and index

- `0x57c9f71`: box `+0x39fd` (tce) clear gives tag `0xdd`.
- `0x57c9f7e`..`0x57c9f8c`: `[arg+0x48] - 0x2761` compared unsigned with `-0x275c`; the tool's model accepts exactly 5..=10080 (10076 values). Otherwise `0x57c9f8e` stores tag `0xd1` and the value at `[out+0x8]`.
- `0x57c9fb0`..`0x57c9fcb`: `[arg+0x38] / 10000` (magic `0x346dc5d63886594b`, shift 11) must be below box `+0x7d0`; `0x57c9ff9`/`0x57ca000` index `0x510`-byte elements at box `+0x7c8`. Box `+0x7c0` is Locus `cls` (#6097), so this is an index into that list (inference). 10080 is the number of minutes in a week (label inference).

## Results and limitations

- Result: begin_block A writes `pmc` only by the reset and the conditional store; the `pmc` + 600 s value is computed and not used in this build.
- Limits: the cursor loop's map and stop condition, the meaning of box `+0x4270`/`+0x710`, the consumer of the checked `+0x48` value, begin_block B, and `mtpt`'s consumer `0x5a1e320` are not mapped.
