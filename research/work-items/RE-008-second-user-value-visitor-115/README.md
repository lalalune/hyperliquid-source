# RE-008: node #115 function `0x30bcb40` (121st stage): a second visitor of the per-user value

- Component ID: abci. Question: open PR #6581 found that `0x30bcb40` holds both direct calls to `0x3184540`, a second decoder of the per-user `p` value, and did not map `0x30bcb40`. What structure does `0x30bcb40` read?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6581 and #6239. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, slot and string references, function starts from `.eh_frame_hdr`, direct-call counts and strings are observations. "visitor", "arm", "not seen", "skip" and the field meanings are inferred labels. The binary was not executed.
- Scope included: the key dispatch of `0x30bcb40`, its two key tables, its field table, the start of each field arm, the duplicate-field names, the two calls to `0x3184540` and a count of the direct callers of `0x30bcb40`. Scope excluded: the bodies of the field readers, where the decoded fields are stored, the array form of `0x30bcb40` beyond its call to `0x3184540`, and the caller `0x3314a40`. No gate changes.

## Result

| Index | Key | Arm | Reader (from fixed bytes) |
|---|---|---|---|
| 0 | `u` | `0x30bce6a` | `call 0x2f6b730` with the 4-byte name `Ntli`, result tag 9 |
| 1 | `p` | `0x30bd52f` | not-seen check, then `call 0x3184540` (the second `p` decoder of #6581) |
| 2 | `D` | `0x30bd636` | not-seen check, then `call 0x3215260` |
| 3 | `l` | `0x30bd6aa` | `call 0x2f6fa30` with the 4-byte name `Time`, result tag 9 |
| 4 | `S` | `0x30bd5f9` | seen check, then `call 0x31c32d0`, result tag 9 |
| 5 | `r` | `0x30bd70e` | `call [0x64e2580]` |
| 6 | any other key | `0x30bd5cc` | `call 0x31d5e50` (skip), result tag 9 |

The keys, their order and the names `Ntli` and `Time` are those of the per-user value visitor `0x1a212f0` in #6239 (u 0, p 1, D 2, l 3, S 4, r 5), and the `r` arm reads through the same slot `0x64e2580`. So `0x30bcb40` is a second visitor of the same per-user value `{u, p, D, l, S, r}`, built for the tag-9 result type of #6580 and #6581. It is not a different structure.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/second_user_value_visitor_115.py --check
python3 -m unittest tests.test_second_user_value_visitor_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eleven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the key dispatch

- `0x30bd0fb`: `call [0x64dfca8]` on the key bytes. If the result tag is 1 and the key is 1 byte: `movzx ecx,[r15]`, `add ecx,-0x44`, `cmp ecx,0x31; ja`, then a jump through table `0x6857e0`. `al` is set to 6 first (`0x30bd10b`), so a key that is not 1 byte, or a character outside the table, keeps index 6.
- The other result path (`0x30bd16f`) uses table `0x685718` the same way.
- In both tables the entry for `u` starts `xor eax,eax` (index 0), and the entries for `p`, `D`, `l`, `S` and `r` start `mov al,1`, `2`, `3`, `4` and `5`. All other entries keep or set 6.
- `0x30bd51c`: `movzx eax,al`, then a jump through field table `0x6858a8`. Entries 0 to 6 are the arms in the result table.

## Evidence 2: the field arms

- `0x30bce89`: `lea rdx,[0x45a098]` (`Ntli`, length 4 in `ecx`), `call 0x2f6b730`, `cmp rax,9; jne`.
- `0x30bd52f`: `cmp rbp,0x8000000000000001; jne` (duplicate), then `0x30bd552`: `call 0x3184540`.
- `0x30bd636`: `cmp [rsp+0x50],0x8000000000000001; jne` (duplicate), then `0x30bd65b`: `call 0x3215260`.
- `0x30bd6c8`: `lea rdx,[0x459f78]` (`Time`, length 4), `call 0x2f6fa30`, `cmp rax,9; jne`.
- `0x30bd615`: `call 0x31c32d0`, `cmp rax,9`.
- `0x30bd79a`: `call [0x64e2580]`.
- `0x30bd5dc`: `call 0x31d5e50` with `edx = 1`, `cmp byte [rsp+0xf0],9`.

## Evidence 3: duplicate fields and the second call

- Each duplicate path loads a 1-byte name and the template at `0x43351a` (length byte 0x11, then `duplicate field \``): `p` (`0x30beb47`), `D` (`0x30bebdd`), `r` (`0x30bec6e`), `u` (`0x30bed04`), `l` (`0x30bed9a`), `S` (`0x30bee30`).
- `0x30be015`: the second `call 0x3184540`, in the same function (`.eh_frame_hdr`).
- `0x30bcb40` has one direct caller, `0x3314f4e`, in `0x3314a40`.

## Implementation and comparison

The tool pins 9 instruction byte runs, each with its meaning. It reads both key tables entry by entry and derives the key-to-index map from the first instruction of each target, reads field-table entries 0 to 6, and checks 7 call targets, 2 slot calls, 9 `lea` targets with their strings, the function that holds each of 5 call sites, and the exact direct `call rel32` sites in `.text` for two functions. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternative considered: running the visitor on a sample input (not allowed for this repository).

## Results and limitations

- Result: `0x30bcb40` is a second visitor of the per-user value, with the same six keys in the same order as `0x1a212f0` (#6239). Field 1 (`p`) is the second `p` decoder `0x3184540` from #6581.
- Limits: the reader bodies (`0x2f6b730`, `0x3215260`, `0x2f6fa30`, `0x31c32d0`, `0x31d5e50`), the store offsets, the array form and the caller `0x3314a40` are not read. That the field meanings match #6239 is inferred from the keys, the order, the two names and the shared slot. Direct-call counts cover `call rel32` only.
