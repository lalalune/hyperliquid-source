# RE-008: node #115 third abci step `0x2d25620` (sixty-eighth stage)

- Component ID: abci. Question: #6040 found four callers of the l1-hash helper `0x452aab0` besides the layout-A and layout-B steps. Three load `node/src/gossip_config.rs` and are left alone here. The fourth, `0x2d25620`, loads the freeze assertion and both snapshot labels. What is it, and how is it reached?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #6006 and #6040. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, call and reference targets, relocations, strings, Location records, FDE extents and call censuses are observations. "Layout A", "step", "wrapper", "task poll", "digest step", "non-validator catch-up" and "snapshot" are inferred labels. The binary was not executed.
- Scope included: the step's opening, its snapshot label and l1-hash call, its periodic path set-up up to the date step, its two direct callers and their callers up to the task poll, the digest step it calls, and a call census. Scope excluded: the wrapper `0x2d23610` body beyond its string references, the shim `0x2d275d0` body, the 45 calls to `0x2666c80`, the folder clean-up slot `0x64e1220` and its target, and the networking side of the task poll. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/third_step_caller_115.py --check
python3 -m unittest tests.test_third_step_caller_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the step uses layout A

The 0x3c bytes at `0x2d25637` equal the bytes at `0x5a07ed7` in the layout-A step `0x5a07ec0` (#6006):

- `mov rsi, [rsi+0x450]` (the box), `mov r15, [rsi+0x28]` (the height);
- the `% 10000` multiply/rotate/compare (`0xd288ce703afb7e91`, `0x68db8bac710cc`);
- `cmp dword [rsi+0x10e8], 1` and `cmp [rsi+0x10f0], r15` (the layout-A freeze height).

Only the register choice before the window (`r13`/`r14` against `r14`/`rbx`) and the frame size (0x218 against 0x1b8) differ. The step is 0x1fa3 bytes; the A step is 0x85c.

## Evidence 2: how it is reached

| Site | In | Calls |
|---|---|---|
| `0x2d24ed9` | wrapper `0x2d23610` | `0x2d25620` |
| `0x2d2766f` | shim `0x2d275d0` | `0x2d25620` |
| `0x27745e0` | `0x2774590` | wrapper `0x2d23610` (its only direct call) |
| `0x2b1e3ee` | task poll `0x2b1df60` | `0x2774590` (its only direct call) |
| `0x2b1e1f8` | task poll `0x2b1df60` | shim `0x2d275d0` (its only direct call) |

- `0x2b1df60` has no direct call; its only reference is the relocation at `0x6449fb0`. It loads `non-validator abci state not caught up yet` (`0x2b1e879`), `using initial abci state from non-validator` (`0x2b1eb71`) and `client block recver ended before valid block` (`0x2b1efbf`).
- The wrapper loads `new abci digests reached quorum` (`0x2d2471e`) and the #6023 digest panic template `0x44c993` (`0x2d2511b`).

Inference: this is a third copy of the layout-A step, driven by a task that catches up from blocks received from a non-validator. The task's networking side is not followed.

## Evidence 3: its own digest step

- `0x2d25712` calls `0x2bb37c0` with `rdx = r13+0x330` (the abci_hashes writer, #6033) and `rcx = r13+0x20` (the observer). This is the only call to `0x2bb37c0`.
- `0x2bb37c0` and the A digest step `0x548dad0` (#6024) are both 0x203 bytes. Of 82 differing bytes, 34 are rel32 fields of calls at the same offset in both, 11 four-byte windows are RIP displacements that reach the same address (for example the root-hash slot `0x64e7820` and the observer slot `0x64e1010`), and one window points at two Location records that both decode to `l1/src/abci/abci_hash.rs:28:37`. The tool rejects any other difference.

## Evidence 4: snapshot label, l1 hash and periodic path

- `0x2d262ac` `test bl, bl` gates the block. `0x2d262ca`/`0x2d262d1` load `freeze` and `periodic`; `test sil, sil` / `cmovne` picks `freeze` when `sil` is set; `lea rcx, [rax*2+6]` gives length 6 or 8.
- `0x2d262ea` calls `0x22ed1f0`, a 0x51a-byte function with three direct callers that loads the same WARN template `0x448ef9` as the layout-A linked-abci-state step `0x5485a60` (#5999).
- `0x2d26391` calls the l1-hash helper `0x452aab0` with `edx = 1` (#6039).
- Slot `0x64e0f58` then `cmp al, 2`: from hour 2 it formats `{}/data/{}` (`0x448b77`) with the periodic slice `0x646e9f0` (#5970) and steps the date back one day. The clean-up call that follows is not mapped.

## Evidence 5: call census

- All 45 direct calls to `0x2666c80` in `.text` are inside this step.
- The step makes no direct call to the A digest step `0x548dad0`, the l1-map insert `0x5a046f0` or the `visor_abci_state` wrapper `0x5942b40`.

## Implementation and comparison

The tool pins eight instruction byte runs, eight direct calls, eleven RIP references, seven strings, one 0x3c-byte opening comparison, a byte-class comparison of the two digest steps, and five call censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: a full byte comparison of the two steps (they differ in size, so not possible); emulation (not allowed for this repository).

## Results and limitations

- Result: `0x2d25620` is a third, larger layout-A step with its own digest step. It is reached from a task poll whose strings describe catching up from a non-validator, not from the slow or fast engine.
- Limits: what the 45 calls to `0x2666c80` do; whether the step inserts into the digest or l1 maps inline; the wrapper and shim bodies; the networking side of `0x2b1df60`; the clean-up call target.
- Next lead: the 45 calls to `0x2666c80` and whether the step keeps the digest and l1 maps the way the A step does.
