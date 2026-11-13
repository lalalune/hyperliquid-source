# RE-008: node #115 hash_signature_tracker default record, sender replace and tag recorder (67th stage)

- Component ID: abci. Question: #6054 (66th stage) left open the starting value of the per-height byte `+0x20`, what the sender insert `0x4dd4f80` does with a repeated sender, and what the recorder behind slot `0x64e4ea8` does with tags 10 and 11.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6053 and #6054. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, offsets, constants, relocations, Location records and call or reference censuses are observations. "Default value", "unresolved", "replace", "recorder" and "registry" are inferred labels. The binary was not executed.
- Scope included: the default-value builders in `0x4da61f0` and `0x4da4b90`; the resolve test and store in the insert `0x537b870`; the hit path of `0x4dd4f80`; the recorder `0x4524e40` and the map clear `0x4524c20`; the four tag sites in the two updates. Scope excluded: the map insert `0x3cded00`, the B-tree and ring inserts behind the or-insert (`0x51ec6b0`, `0x57eeaf0`), the miss path of `0x4dd4f80`, and any reader of the recorder map other than the clear. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hash_signature_tracker_record_115.py --check
python3 -m unittest tests.test_hash_signature_tracker_record_115
```

The tool reads the ELF only. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: a new height starts unresolved

The insert `0x537b870` gets or creates the height's value with `0x4da61f0` (call at `0x537bf60`); the twin insert `0x537aa60` uses `0x4da4b90` (call at `0x537b150`). Both build the same default on the stack before inserting it:

| Instruction | Bytes | Value field |
|---|---|---|
| `mov qword [rsp+0x8], 0` | `48 c7 44 24 08 00 00 00 00` | `+0x0` = 0 |
| `mov qword [rsp+0x10], 8` | `48 c7 44 24 10 08 00 00 00` | `+0x8` = 8 |
| `xorps xmm1, xmm1; movups [rsp+0x18], xmm1` | `0f 57 c9`, `0f 11 4c 24 18` | `+0x10..+0x20` = 0 |
| `mov byte [rsp+0x28], 1` | `c6 44 24 28 01` | `+0x20` = 1 |

The words `{0, 8, 0, 0}` are the empty collection form seen in #6049. Byte `+0x20` = 1 means unresolved: the insert tests it at `0x537c09f` and writes 0 at `0x537c192` when the quorum check passes (#6053). The 32-byte key at `+0x21` is not written by the default; it is copied in only on resolve.

## Evidence 2: a repeated sender replaces its value

`0x4dd4f80` compares 20-byte keys (`mov edx, 0x14` at `0x4dd5372`, then the memcmp slot). On a hit it copies the old 0x48-byte value to the output (`mov rcx, [r13+0x40]` / `mov [rax+0x48], rcx` and four 16-byte moves), writes the new value over it (`mov [r13+0x40], rcx` at `0x4dd5447`) and returns tag 1 (`mov ecx, 1` at `0x4dd544b`). This matches the key insert `0x4dd26f0` (#6054). The insert calls the sender insert for collection `+0x20` (`0x537c106`) and the key insert for collection `+0x0` (`0x537c152`).

## Evidence 3: tags 10 and 11 go into a global registry

- Slot `0x64e4ea8` is relocated to `0x4524e40`, which has no direct caller. 1047 `call [rip+slot]` sites use it.
- Under a lock word at `0x64fdb00` (`lock cmpxchg` 0 → 8 at `0x4524e58`), it copies the first 0x14 bytes of the Location in `rsi` (`movups xmm0, [rsi]`, `mov eax, [rsi+0x10]`), zero-extends the tag (`movzx edx, dil`) and inserts both into the map at `0x64fdb08` through `0x3cded00`. A Once cell at `0x64fdb28` guards first use.
- The only other code that addresses `0x64fdb00`, `0x64fdb08` or `0x64fdb28` is `0x4524c20` (slot `0x64e6b50`, 3 slot calls), which resets the map to `{0, 8, 0, 0}`. A RIP-relative census finds 30 references, all inside these two functions.
- The two updates pass tag 10 (`0x5afaa83`, `0x5afac32`) and tag 11 (`0x5afb063`, `0x5afb212`) with Location records `0x64bc860` (`l1/src/abci/hash_signature_tracker.rs:107:28`) and `0x64bc878` (`:123:32`).

Inference: the recorder keeps the last Location reached per tag for diagnostics. It writes no log line and the tracker never reads the map back.

## Results and limitations

- Results: new height records start unresolved (`+0x20` = 1) with an empty collection; repeated senders and keys replace their earlier value; tags 10 and 11 only feed a global (tag → Location) registry.
- Limits: the map insert `0x3cded00` is identified by its call shape only; who reads the registry through other means (for example a panic or diagnostic hook) is not traced; the miss path of `0x4dd4f80` and the conditions gating the two tag sites per update are not bound.
- Next lead: the conditions before each recorder call in `0x5afa7f0` (`jo` at `0x5afaa72`, 16-byte compare at `0x5afac24`).
