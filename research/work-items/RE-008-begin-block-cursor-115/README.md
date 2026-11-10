# RE-008: node #115 begin_block A cursor loop (stage 95)

- Component ID: abci. Question: #6164 found that begin_block A (`0x54b66b0`) moves a 20-byte cursor at box `+0x42b1` in a loop `0x54bffb9..0x54c0188` and sets box `+0x42b0` to 1. It left open what the loop walks, what limits it, and what each step does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6095 (Exchange field names) and #6164. It does not depend on their files; the field names are cited, not imported.
- Claim status: instruction bytes, offsets, call targets, relocations and FDE extents are observations. "Cursor", "range", "wrap", "collected" and the field roles are inferred labels. The binary was not executed.
- Scope included: the entry guard, the cursor copy, the two iterator builds, the loop counter and chain order, the per-step filter, the wrap check that writes `pmc`, and the per-key call after the loop. Scope excluded: the bodies of the range builders `0x4dcdfc0` / `0x4dce210`, the iterator step `0x4e18aa0`, the lookup `0x4ef4480`, the predicate `0x3693030`, the per-key work `0x5582180`, and begin_block B. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/begin_block_cursor_115.py --check
python3 -m unittest tests.test_begin_block_cursor_115
```

The tool reads the ELF only. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review; the tool does not read them.

## Fields involved

| Name | Where | Source |
|---|---|---|
| `pmn` | Exchange index 55, box `+0x4270`, u64 | #6095 |
| `pmi` | Exchange index 54, box `+0x42b0` (tag) / `+0x42b1` (20-byte key) | #6095 |
| `blp` | Locus field, box `+0x670..+0x7c0`; the loop uses `+0x6f8` (map), `+0x710` (word), `+0x7b8` (byte) | #6097 |
| `pmc` | ExchangeMisc `+0xe8`, box `+0x39f0` | #6103 |

## Evidence

1. **Entry guard.** `0x54bfdf5` `cmp qword [r15+0x4270], 0` and `0x54bfdff` `cmp qword [r15+0x710], 0`. Either zero jumps to `0x54bfe3c`, which stores `pmc` = (`0xf6401a`, 0), the unset value.
2. **Cursor.** `0x54bfe17` tests the `pmi` tag for 1. If set, the 20 bytes at `+0x42b1` are copied (`0x54bfe21`, `0x54bfe2c`); otherwise a zero key is used.
3. **Two iterators over the map at `+0x6f8`.** `0x54bfea1` calls `0x4dcdfc0` with bounds tag 1 plus the key and tag 2 (`0x54bfe87`, `0x54bfe8c`). `0x54bfece` calls `0x4dce210` with the key. The loop takes entries from the first (`0x54c002b`) until it is marked done (tag 3, `0x54c0035`), then from the second (`0x54c004f`).
4. **Limit.** `0x54bff42` loads `pmn` and enters the loop at `0x54c0013` (`jmp 0x54bffd0`), which decrements it and stores the remainder at `rsp+0xd0`. Each step decrements once; the loop ends when it reaches 0 (`0x54c000a`) or when both iterators end.
5. **Each step.** The yielded 20-byte key becomes the new `pmi` key and the tag is set to 1 (`0x54c008f`, `0x54c009d`, `0x54c00a9`). The key is looked up by `0x4ef4480`; a miss uses the lazy default cell `0x64fd9b0` (slot `0x64e71a8`). The key is pushed onto a Vec of 20-byte entries only when the record byte `+0x3c` is 4 (`0x54c00ef`), box `+0x7b8` bit 0 is clear (`0x54c00ff`) and slot `0x64e7190` (`0x3693030`) returns true for the entry value (`0x54c010f`).
6. **After the loop.** If `pmi` is set (`0x54c0279`) and `memcmp(new key, entry key, 20) <= 0` (`0x54c028a`, `0x54c029a`), `pmc` takes the block date-time (`0x54c02a1`). Then every collected key is passed to `0x5582180` with `ecx = 0`, `r8d = 1` (`0x54c0332`..`0x54c0345`).

## Reading (inference)

The loop is a bounded, resumable walk over a map keyed by 20-byte addresses: it starts after the stored cursor, wraps to the start, visits at most `pmn` entries per block, and remembers where it stopped in `pmi`. When a block's walk passes its own starting point (`new key <= entry key`), it records the time in `pmc`. The keys it collects get the per-key action `0x5582180`. What that action does, and what the map holds, are not mapped here.

## Results and limitations

- 45 instruction byte runs, 6 direct calls, 3 RIP references and 2 relocations are pinned. Census: `0x4dcdfc0` and `0x4dce210` each have 2 direct calls, `0x5582180` has 4. 10 tests pass, 8 of them mutation controls.
- Limits: the iterator bounds' exact semantics (Included/Excluded) are read from tag values only; the map's value type, the lookup table, the predicate and the per-key action are not mapped; begin_block B is not checked.
