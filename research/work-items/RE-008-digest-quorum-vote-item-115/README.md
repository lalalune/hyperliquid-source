# RE-008: node #115 digest quorum vote insert (65th stage): how one vote becomes a signer entry

- Component ID: abci. Question: #6052 found the four vote handlers and the store update `0x5afa7f0`, which ends in the only call to the vote insert `0x537b870`. #6051 found how a resolved height picks its digest. This packet asks how the insert adds one vote: which signer parts it keeps, when it refuses a vote, what it adds where, and when the height becomes resolved. It also compares the second store update `0x5afadd0` with the first.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6051 and #6052. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, Location records, FDE extents and call censuses are observations. "Signer", "key", "address", "member", "census", "cap", "resolved", "quorum" and "collection" are inferred labels from shapes, sizes and the #6051/#6052 results. The binary was not executed.
- Scope included: the candidate built in `0x5afa7f0`, the vote insert `0x537b870` (part tags, membership checks, resolved-height skip, census cap, get-or-create calls, quorum check before and after, collection adds, resolve write), the first call inside `0x5373810`, and a byte comparison of `0x5afa7f0` with `0x5afadd0`. Scope excluded: the bodies of `0x4e40990`, the get-or-create helpers, `0x4dd4f80`, `0x4dd26f0`, slot `0x64e6478`, slot `0x64e6ac0`, the signature recovery `0x1536a90`, and what box `+0xd88` and `+0x3f08` hold beyond what #6052 shows. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/digest_quorum_vote_item_115.py --check
python3 -m unittest tests.test_digest_quorum_vote_item_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the signer candidate

`0x5afa7f0` builds a candidate on its stack and passes `rsp+0xd8` as `r8` to `0x537b870` (`call` at `0x5afab8f`, the only direct call):

| Offset | Content | Set from |
|---|---|---|
| `+0x0` | tag byte (`0x5afaaeb`, `r15b`) | 1 when slot `0x64e6478` returns tag word `0x1a2` (`0x5afa9ee`) |
| `+0x1..+0x21` | 32-byte key | that slot's result |
| `+0x21` | tag byte (`0x5afaaf3`, `r14b`) | 1 when the sender was found in the 20-byte-key B-tree (#6052) |
| `+0x22..+0x36` | 20-byte sender | the vote |

The insert reads `[r8]` (`0x537b8ae`) and `[r8+0x21]` (`0x537b8b2`) and keeps each part only when its tag is 1 (`0x537b8cd`, `0x537b908`). It then handles each kept part in turn.

## Evidence 2: refusals

For each part, before anything is added:

1. A 20-byte part must be found in a 20-byte-key B-tree reached through a stack argument (`memcmp` length `0x14` at `0x537bb19`). A 32-byte part must make slot `0x64e6ac0` return non-zero (`0x537bbed`). Otherwise the part is skipped.
2. If the height's value exists and is resolved (byte `+0x20` is 0), the part is skipped unless the selected key at `+0x21..+0x41` equals the vote digest (`0x537b99b`..`0x537b9bf`).
3. If the (height, digest) pair does not exist yet, a census `0x4e40990` (closure table `0x64a7f08`) runs over the store; a result above `0x897` (2199) skips the part (`0x537bf33`). What the census counts is not mapped.

No error tag is returned for a skipped part.

## Evidence 3: add and resolve

1. The height's value is fetched or created (`0x4dc8170`, `0x4da61f0`), then the digest's inner value (`0x4dcd300`, `0x4da5bc0`).
2. If the height is unresolved (`+0x20` != 0, `0x537c09f`), `0x5373810` runs first (`0x537c0c0`); if resolved, the result is taken as true (`mov bpl, 1` at `0x537c10d`). `0x5373810` calls the #6051 stake check `0x36c7f70` (`0x53738fa`).
3. A 20-byte part is added to the inner value's collection at `+0x20` (`0x537c0ed`, `0x4dd4f80`); a 32-byte part to the collection at `+0x0` (`0x4dd26f0`).
4. If the check was false before, `0x5373810` runs again (`0x537c180`). If it is now true, the height is resolved: `+0x20` = 0 (`0x537c192`) and the digest is copied to `+0x21..+0x41` (`0x537c1a8`, `0x537c1ad`). This is the field #6051 and #6049 read.

`0x5373810` has four direct calls: `0x537c0c0` and `0x537c180` here, and `0x537b2b0` and `0x537b370` in the twin insert `0x537aa60`.

Inference: a vote that repeats an existing signer goes through the same collection add; whether the add replaces or ignores it depends on `0x4dd4f80`/`0x4dd26f0`, which are not mapped.

## Evidence 4: the twin update

`0x5afa7f0` and `0x5afadd0` are both 0x5d3 bytes. Comparing them byte by byte, 26 differing rel32 fields name the same absolute target from both copies. The other differences are three call targets (`0x57c9430`/`0x57c96c0`, `0x537b870`/`0x537aa60`, `0x5376540`/`0x5376f80`) and one immediate, `mov edi, 0xa` versus `0xb`, in two places (`0x5afaa84`, `0x5afac33`). Both use Location records in `l1/src/abci/hash_signature_tracker.rs` (lines 107, 123, 174, 184). So the `+0x3e50` store follows the same vote logic; what the `0xa`/`0xb` argument selects is not mapped.

## Implementation and comparison

The tool pins 32 instruction byte runs, the Location file string and four Location records, recomputes the direct-call census of the two inserts and the quorum check in one pass over `.text`, and recomputes the twin comparison. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: emulating the insert (not allowed); decoding the census closure (bounded out).

## Results and limitations

- Result: a vote adds each verified signer part to the per-height, per-digest inner value, refuses new pairs past a census of 2199, and resolves the height the first time the #6051 check passes. Resolution writes the digest the quorum entry builder later returns.
- Limits: the census count, the get-or-create default for byte `+0x20`, duplicate handling inside the collection adds, slot `0x64e6478` and slot `0x64e6ac0`, the `0xa`/`0xb` argument, box `+0xd88` and `+0x3f08` beyond #6052.
- Next lead: the census closure `0x64a7f08` behind the 2199 cap.
