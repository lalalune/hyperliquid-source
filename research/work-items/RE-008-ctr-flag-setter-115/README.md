# RE-008: node #115 ctr flag setter `0x55817e0` (stage 98)

- Component ID: abci. Question: stage 97 (open PR #6207) found that in the per-key action `0x5582180` the local flag `[rsp+0x28]` becomes 1 only after the call to `0x55817e0` at `0x5583117`, and that Locus `ctr` (box `+0xab0`) is incremented when the flag is set and `[rsp+0x58]` is not zero. It left open what `0x55817e0` does and what `[rsp+0x58]` is.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6206 and #6207. It imports helpers from the merged `tools/freeze_snapshot_115.py` only.
- Claim status: instruction bytes, call targets, strings, Location records, relocations and call censuses are observations. "key", "membership", "move_token helper", "vector form" and "map form" are inferred labels. The binary was not executed.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/ctr_flag_setter_115.py --check
python3 -m unittest tests.test_ctr_flag_setter_115
```

The tool reads the ELF only. The three `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the flag means "the call has run", not "the call succeeded"

At the call site (`callsite-55830d8.objdump.txt`) the per-key action:

- skips the call while `[rsp+0x23] | [rsp+0x28]` has bit 0 set (`0x55830d8..0x55830e3`);
- writes the qword 2 to `[rsp+0xb0]` (`0x55830e5`), sets `ecx = 0` (`0x558310a`) and `r9 = &[rsp+0xb0]` (`0x558310c`), and calls `0x55817e0` (`0x5583117`);
- then stores `al = 1` into the flag (`0x5583120`, `0x5583122`) without reading any result.

`0x55817e0` writes no result for its caller (Evidence 2), so the flag records only that the call has run once.

## Evidence 2: what `0x55817e0` does

Function `0x55817e0..0x5581caa` (`setter-55817e0.objdump.txt`), with `r15` = box, `r14` = record, `rbx` = the 20-byte key argument (`rdx`):

1. **Key tag.** It loads `[r9]` (`0x558180a`), subtracts 2 with a floor of 1 (`0x5581810..0x5581819`). Tag 2 takes the path at `0x5581897`, which uses `rbx` as the key. The call site passes tag 2.
2. **Membership.** It compares box `+0x6c8` with `0x8000000000000000` (`0x558184e`). Equal: it searches the vector at `+0x6d0`/`+0x6d8` through `0x35bf460`. Otherwise it looks the key up in the map at `+0x6c8` through `0x4556410`. A key already present skips to the tail at `0x5581bf9`.
3. **Checks.** For a key not present it calls `0x5609fb0` with `r8d = 3` (`0x5581946`). It then calls slot `0x64e7180` (relocated to `0x369b360`) on Locus `blp` (`lea rdi, [r15+0x670]`, `0x55819e1`); if that returns true it calls `0x5609fb0` again with `r8d = 0` (`0x5581a37`). The other path (tag 0/1) calls `0x5609fb0` with `r8d = 3` at `0x5581ac0` and `0x5581b7d`.
4. **Results.** Each `0x5609fb0` result is compared with tag `0x1a2` (`0x558194b`); any other result is moved to a stack copy and dropped through `0x5630000`.
5. **Tail.** Every path ends at `0x5581bf9`, which calls `0x5580d10` (`0x5581c1c`) with `r8d = 0`; a non-`0x1a2` result is dropped through `0x5630000` (`0x5581c93`). The function then returns.

`0x5580d10` loads the strings `move_token to_spot: ` (`0x432bcb`) and `move_token from_spot: ` (`0x438c95`), and passes the Locations `l1/src/qtys/impl_wei.rs:6:1` (`0x6487478`) and `l1/src/qtys/impl_ntl.rs:70:1` (`0x64a9918`) to the registry slot `0x64e4ea8` (#6056). Inference: it moves a token balance between spot and perp for the key.

Direct callers of `0x55817e0`: `0x5583117` and `0x55845da` in `0x5582180`, `0x5588e6f` in `0x5588d90`, `0x558942a` in `0x55890d0`.

## Evidence 3: `[rsp+0x58]` is the action's `r8` argument

The only store to `[rsp+0x58]` in `0x5582180` is `mov [rsp+0x58], r8` at `0x55821af`. The `ctr` update (`ctr-inc-5583256.objdump.txt`) tests `[rsp+0x58] != 0` and the flag (`0x5583256..0x558325f`), then saturates `+0xab0` + 1 (`0x5583273..0x5583288`). So the condition stated in #6206 (`r8 != 0`) and in #6207 (`[rsp+0x58] != 0`) is the same test.

## Implementation and comparison

The tool pins 28 instruction byte runs, 6 direct calls, 7 RIP-relative references, 2 strings, 2 Location records and 1 relocation, and recomputes the caller and check-call censuses. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: the per-key action runs `0x55817e0` at most once per call and then sets the flag; `0x55817e0` checks the key against Locus `blp`, runs `0x5609fb0` (mode 3, then mode 0 when the blp check passes) and the move_token helper `0x5580d10`, and drops every error. `ctr` counts per-key action calls that ran this step with a non-zero `r8` argument.
- Limits: the bodies of `0x5609fb0` (modes 0 and 3), `0x369b360`, `0x35bf460` and `0x4556410`; what `0x5580d10` moves and where; the other three callers' arguments; the meaning of Locus `cls` element list byte `+0x1d`.
- Next lead: `0x5609fb0` and its two modes.
