# RE-008: node #115 abci digest check in the step wrappers (46th stage)

- Component ID: abci. Question: #6021 found that the step wrapper `0x5a04e40` compares 32 bytes and, on a mismatch, panics with "computed abci digest at height=... does not match quorum value ...". It left open which value is which, what fills each side, when the check runs, and whether both box layouts (#6006) carry it.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6019 and #6021. It imports helpers from the merged `tools/freeze_snapshot_115.py` only.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, FDE extents and call or pattern censuses are observations. "Computed digest", "quorum value", "height", "map", "B-tree", "ring" and "trim" are inferred labels from the panic text, the shapes and the sizes. The binary was not executed.
- Scope included: the compare loops in `0x5a04e40` (layout A) and `0x5a06600` (layout B); the map at engine value `+0x400`; the insert `0x5a03fa0` and its two call sites in the A and B steps; the step condition that guards the insert; the max-key bookkeeping and trim in the A wrapper. Scope excluded: the bodies of the digest functions `0x548dad0`/`0x548d8c0` and their callee through slot `0x64e7820` (`0x41c5140`); where the 0x68-byte entry slice comes from before the wrapper; the dump function `0x4e4a740`; the third panic site in `0x2d23610`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_digest_check_115.py --check
python3 -m unittest tests.test_abci_digest_check_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only.

## Evidence 1: the compare and which side is which

`0x5a05ca1..0x5a05d35` in `0x5a04e40` walks a slice of 0x68-byte entries (`add r13, 0x68` at `0x5a05d2e`). For each entry it looks up the u64 at entry `+0x0` in a map at engine value `+0x400` (`lea rbp, [r12+0x400]`, `0x5a05cc8`):

- If `+0x400` holds `0x8000000000000000`, the map is a B-tree: root at `+0x408`, height at `+0x410`, u64 keys at node `+0x170`, a u16 length at node `+0x1c2`, children at `+0x1c8`, 32-byte values before the keys.
- Otherwise `0x57f8bb0` searches a ring of 0x28-byte entries (buffer `+0x408`, head `+0x410`, length `+0x418`; key then 32 bytes).
- A key that is not present skips the entry (`test al, 1` / `jne` at `0x5a05dfb`, and the B-tree path's exits).
- When the key is present, the 32 bytes at entry `+0x48..+0x68` are compared with the map's 32 bytes by two `pcmpeqb`; any byte difference (`cmp eax, 0xffff` / `jne`, `0x5a05d23`) jumps to `0x5a060ec`, whose panic uses template `0x44c993` ("computed abci digest ... does not match quorum value").

The map is filled by the step (Evidence 2), so the map value is the computed digest and entry `+0x48` is the quorum value. This corrects the brief from #6021, which named `r13+0x48` the computed side.

`0x5a06600` (layout B) holds the same loop with `r15` as the engine value: `lea rbp, [r15+0x400]` at `0x5a074f6`, the compare at `0x5a07527`, mismatch to `0x5a0793f`, template reference at `0x5a07a54`. The byte pattern `movdqu xmm2,[r13+0x48]; pcmpeqb; movdqu xmm0,[r13+0x58]` occurs exactly twice in `.text`, once in each wrapper.

## Evidence 2: what fills the map, and when

- In the A step `0x5a07ec0`, `0x5a07f85` loads the box divisor at `+0x39c8`. When `bpl` is clear, the block takes the digest path only when height % divisor is 0. It calls `0x548dad0` (into `rsp+0x130`) and then `0x5a03fa0` with `lea rdi, [r14+0x400]` and the height (`0x5a07fe5`).
- The B step `0x5a08720` does the same with the divisor at `+0x4538` (the #5970 snapshot divisor), `0x548d8c0`, and `0x5a03fa0` (`0x5a08845`). `0x5a03fa0` has exactly these two direct callers. `+0x4538 - +0x39c8 = 0xb70`, the layout shift from #6006.
- `0x5a03fa0` inserts through `0x4dd45c0`, then trims when the map length at `+0x18` is at least 0x33 (`cmp rdx, 0x33`, `0x5a03fc1`).
- `0x548dad0` reads the monotonic clock twice and records into an observer through slot `0x64e1010` (relocated to `0x1547530`), so the digest computation is timed (#5045 observer).

## Evidence 3: bookkeeping around the check

- Before the compare, `0x5a05bba..0x5a05c0f` takes the largest entry key and stores (tag, max) at engine value `+0x10`/`+0x18`.
- After the compare, when the tag byte at `+0x10` is set (`0x5a05ea1`), the wrapper computes max + 1 (saturating, `0x5a05eb2`) and passes it to `0x4de5ad0` (`0x5a05ee3`), whose result replaces the map header at `+0x400`; reading this as "keep keys at or above max + 1" is an inference. It then calls the step (`0x5a05fc9`).

## Results and limitations

- Result: the step computes a 32-byte digest only on heights that are a multiple of the snapshot divisor (or when `bpl` is set) and keeps up to about 50 of them by height. The wrapper then checks every incoming quorum entry whose height has a computed digest, and panics on any mismatch. Entries at heights without a computed digest are not checked. Both layouts carry the same check.
- Limits: which hash `0x548dad0`/`0x41c5140` computes, and over which state; the meaning of `bpl`; where the 0x68-byte entry slice is built (the loop at `0x5a053b0` and `0x4dd0010` were not followed); the meaning of entry `+0x8..+0x48`; the third panic site in `0x2d23610`, which uses another code shape; the dump `0x4e4a740`.
