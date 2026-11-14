# RE-008: node #115 JSON position reader (118th stage): M rejects 0 and defaults to 20

- Component ID: abci. Question: open PR #6577 found a pretty JSON writer and a JSON reader `0x402e7c0` for the per-user value, with a position field matcher `0x4455890`. Open PR #6456 found that the MessagePack position decoder rejects an M of 0 and reads a missing M as 20. Does the JSON reader use the same two rules for M?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6577 and #6456. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, relocation values and strings are observations. "Not seen", "default", "error", "unsigned", "signed" and the field names are inferred labels. The binary was not executed.
- Scope included: the field dispatch of `0x402e7c0`, its M arm, the M value reader `0x3ef32a0`, the end-of-map and sequence defaults, the store of M in the result, and the expected text. Scope excluded: the number parser `0x3ef2440`, the bodies of the two error slots, the other position fields, the caller chain of `0x402e7c0`, and the caller `0x32d3c90` of the second matcher. No gate changes.

## Result

| Case | MessagePack decoder (#6456) | JSON reader (this packet) |
|---|---|---|
| M missing | default 0x14 (20) | default 0x14 (20), map and sequence form |
| M = 1..0xffffffff | accepted | accepted (unsigned or signed integer) |
| M = 0 | rejected, `expected a nonzero u32` | rejected through the same expected vtable `0x646c050` (`a nonzero u32`) |
| M above 0xffffffff or negative | rejected | rejected |
| M is not an integer | — | rejected (Unexpected tag 3) |
| M given twice | duplicate field | duplicate field `M` |

So the JSON reader follows the same M rules as the MessagePack decoder. Both forms of the per-user value read M the same way.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_json_m_115.py --check
python3 -m unittest tests.test_position_json_m_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eight `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: field dispatch and the M arm

- `0x402e7c0` calls the matcher `0x4455890` (`0x402ea50`) and jumps through the table `0x7c01c0` by the field index byte (`0x402ea60`). The six entries are `0x402ea75`, `0x402ec1b`, `0x402eb63`, `0x402ebbd`, `0x402eaec` and `0x402ec73`. Index 2 (M, see #6577) goes to `0x402eb63`.
- The M arm starts with `cmp dword [rsp+0x50],0; jne 0x402f1dc`. `0x402f1dc` loads the 1-byte name `M` (`0x7c26e9`) for the duplicate-field error. So 0 at `rsp+0x50` means "M not seen".
- After `:` (`0x402ecec`), the arm calls `0x3ef32a0` (`0x402ed0c`). On tag 1 it takes the error path. Otherwise it keeps the 4-byte result at `rsp+0x50` (`0x402ed1c`).

## Evidence 2: the M value reader rejects 0

- `0x3ef32a0` calls the number parser `0x3ef2440` (`0x3ef3343`). Kind 3 passes the parser's error.
- Kind 1 (`cmp ecx,1; je 0x3ef33c5`): `movabs rcx,0xffffffff00000000; lea rdx,[rax+rcx]; inc rcx; cmp rdx,rcx; jb 0x3ef341d`. Only 1..0xffffffff pass. Others, 0 included, go to `0x3ef341d`: Unexpected tag 1 with the value.
- Kind 2 (`cmp ecx,2; jne 0x3ef33ea`): the same range test with `jae 0x3ef33db` (keep). Others get Unexpected tag 2.
- Any other kind goes to `0x3ef33ea`: Unexpected tag 3.
- The tag 1 and 2 paths call slot `0x64e0910` (`0x3ef3438`, relocated to `0x5c54c30`). The tag 3 path calls slot `0x64e0900` (`0x3ef3405`, relocated to `0x5c54bd0`). Both pass the expected vtable `0x646c050` (`0x3ef3427`, `0x3ef33f4`).
- The vtable entry `0x646c068` is relocated to `0x38dbaa0`, which writes the 13-byte text `a nonzero u32` (`0x9451ad`). The MessagePack decoder in #6456 uses the same entry.

## Evidence 3: default 20 and the stored field

- End of map (`0x402eec3`): `mov r12d,[rsp+0x50]; test r12d,r12d; cmove r12d,ecx` with `ecx = 0x14`. A field that is still 0 gets 20.
- Sequence form (`0x402ef42`): `mov r12d,0x14`, then the next element is read with `0x3ef32a0` (`0x402ef7f`). It replaces r12d only on success. The element order of the sequence form is not mapped here.
- The result stores M with `mov [rbx+0x38],r12d` (`0x402f0be`). The writer in #6456 reads M at `+0x38`.

## Note: the second matcher

`0x4455970` (called from `0x32d3c90`, #6577) has the same key compare bytes as `0x4455890` for `leverage`, `szi` and `entry_ntl`. The only difference checked is the success tag byte: 0 in `0x4455890`, 9 in `0x4455970`. This packet does not map its caller.

## Implementation and comparison

The tool pins 12 instruction byte runs (each with its meaning). It also checks the six field-table entries, five call and branch targets, two slot calls and three relocations, four `lea` targets with two strings, the number-kind tests and both range tests, and the second matcher's compare bytes and tags. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternative considered: reading a sample JSON position with M = 0 by running the code (not allowed for this repository).

## Results and limitations

- Result: the JSON reader treats M as a nonzero u32 with default 20, the same as the MessagePack decoder. Both forms reject 0 with the same expected text.
- Limits: the number parser `0x3ef2440` is not read; the kind numbers 1, 2 and 3 are labels taken from the branches. The bodies of `0x5c54c30` and `0x5c54bd0` are not read; that they build the "invalid value" and "invalid type" errors is an inference. The caller chain of `0x402e7c0` and the caller `0x32d3c90` of the second matcher are not mapped.
