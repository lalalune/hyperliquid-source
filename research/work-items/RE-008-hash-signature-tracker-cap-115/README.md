# RE-008: node #115 hash_signature_tracker per-signer cap, repeated signer and the 10/11 tag (66th stage)

- Component ID: abci. Question: stage 65 (open PR #6053) found that the vote insert `0x537b870` skips a new (height, digest) record when a count from `0x4e40990` is above `0x897` (2199), that a signer is stored in the digest record's sender (`+0x20`) or key (`+0x0`) collection, and that the two updates `0x5afa7f0` / `0x5afadd0` differ by a constant 10 vs 11. It left open what the count counts, what a repeated signer does, and what the constant is.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6052 and #6053. It does not depend on their files.
- Claim status: instruction bytes, call targets, relocations, Location records and the call census are observations. "Signer", "part", "per-signer cap", "found/hit", "replace" and "recorder" are inferred labels. The binary was not executed.
- Scope included: the count `0x4e40990` (its record walk and its two search calls), the hit encodings of the B-tree search `0x4d38340` and the ring search `0x57f39d0`, the hit path of the key collection insert `0x4dd26f0`, and the 10/11 call sites. Scope excluded: the B-tree walk of `0x4e40990`, the sender insert `0x4dd4f80`, the recorder `0x4524e40` body, the 32-byte search `0x4d38590` and ring search `0x57f4490` used for the sender collection, and the per-height record creation. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hash_signature_tracker_cap_115.py --check
python3 -m unittest tests.test_hash_signature_tracker_cap_115
```

The tool reads the ELF only. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the cap counts this signer's other digest records

- `0x4e40990` has exactly two direct calls: `0x537bf2e` in the insert `0x537b870` and `0x537b11e` in its twin `0x537aa60` (the second store's insert). Both build a tag-2 (ring) iterator over the per-height elements of store `+0x18` (0x50 bytes each), put a pointer to the caller's part byte (`lea rax, [rsp+0x1ff]`) in the iterator, pass Location `l1/src/raw_signature_tracker.rs:231:9` (`0x64a7f08`) and compare the result with `0x897`; `ja` skips the new record.
- For each per-height value, the count takes the resolved key `+0x21` only when byte `+0x20` is 0 (`cmove r13, rcx` at `0x4e40c7b`).
- For each digest record of that height, a 32-byte compare with the resolved key (`pcmpeqb` ... `cmp eax, 0xffff; je`) adds 0 for the resolved digest.
- Otherwise the part byte selects the collection (`cmp byte [rax], 1`): 1 → senders at record `+0x20`, else keys at `+0x0`; each may be a B-tree (`0x8000000000000000` marker) or a sorted ring.
- B-tree search `0x4d38340` (32-byte `memcmp`) writes tag 0 when found (`xor ecx, ecx; mov [rax], rcx`); the count adds `tag ^ 1`. Ring search `0x57f39d0` returns 0 on an equal compare (`movzx eax, cl; je 0x57f3b85`); the count adds `rax == 0`.

Inference: the count is the number of unresolved-or-losing (height, digest) records, across all heights in the store, that already list this signer. A signer above 2199 such records cannot open a new record; it can still vote for a digest that already has a record. This replaces the stage-65 brief's reading ("pending pairs in total").

## Evidence 2: a repeated signer replaces its value

The key collection insert `0x4dd26f0` (calls `0x537c152`, `0x537b342`) searches the sorted ring with `0x57f39d0` (`0x4dd2888`). On a hit (`je 0x4dd29db`) it addresses the item by `imul rax, rax, 0x68`, copies the old 0x48-byte value out, writes the new value at item `+0x20` (`movups [r13], ...`, `mov [r13+0x40], rcx`) and returns 1 (`mov ecx, 1`). No item is added. The sender insert `0x4dd4f80` (calls `0x537c106`, `0x537b2f6`) is not mapped here.

## Evidence 3: 10 vs 11 is a tag passed to a recorder

Both updates call slot `0x64e4ea8` (relocated to `0x4524e40`) twice with `rsi` = a Location in `l1/src/abci/hash_signature_tracker.rs` (`0x64bc860` = 107:28, `0x64bc878` = 123:32) and `edi` = the tag: `0x5afa7f0` passes 10 (`0x5afaa83`, `0x5afac32`), `0x5afadd0` passes 11 (`0x5afb063`, `0x5afb212`). The second site in each runs after a failed 32-byte compare. `0x4524e40` takes a global lock word (`0x64fdb00`) and records `dil` with the Location into `0x64fdb08`; the body is not mapped. Inference: the tag tells the two trackers apart in that record.

## Implementation and comparison

The tool pins 44 instruction byte runs, 9 call targets, 11 RIP-relative references, 4 relocations, 2 strings and 3 Location records, and recomputes the call census in one pass over `.text`. Tests change one byte in a copy and expect rejection (8 mutation tests). Alternatives considered: tracing the recorder body (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the 2199 cap is per signer, not a total; a repeated key signer overwrites its value; 10/11 is a recorder tag.
- Limits: the B-tree half of the count's walk, the sender insert `0x4dd4f80` and its hit path, the initial value of per-height byte `+0x20` at record creation, what the 0x48-byte value holds, and what `0x4524e40` does with the tag are not mapped.
- Next lead: the per-height record creation in `0x537b870` (byte `+0x20` start value) and the sender insert `0x4dd4f80`.
