# RE-008: node #115 ExchangeMisc scalar field readers (stage 93)

- Component ID: abci. Question: #6099 placed the 12 ExchangeMisc fields (`msc`, box `+0x3908` in layout A, `+0x4478` in layout B) and gave defaults, but not which code reads the scalar fields `aci`, `mtpt`, `pmc`, `tde` and `tce`, or what they control.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #6023 (abci digest cadence) and #6099 (ExchangeMisc offsets).
- Claim status: instruction bytes, offsets, constants and the operand census are observations. Field names come from #6098/#6099. "Digest interval", "feature gate", "minutes" and "unset" are inferred labels. The binary was not executed.
- Scope included: every `[reg+disp32]` operand (no SIB) at the five field offsets in both layouts; the `aci` reads in both steps; the `tce`/`tde` gates in four handlers; the `pmc` reset and check in begin_block A. Scope excluded: `sgd`, `mou`, `uta`, `vpv`, `sog`, `sre`; what `mtpt` controls after it is passed on; the action names behind the dispatcher stores; `rsp`-relative copies. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/exchange_misc_readers_115.py --check
python3 -m unittest tests.test_exchange_misc_readers_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: operand census

The tool scans `.text` for the 32-bit displacement of each field with a ModRM of `mod=10`, no SIB, after a load, store or compare opcode, and maps each hit to its FDE. Site addresses in `evidence.json` are ModRM addresses.

| Field | ExchangeMisc offset | A box offset | B box offset | Sites A + B |
|---|---|---|---|---|
| `aci` | +0xc0 | +0x39c8 | +0x4538 | 9 + 2 |
| `mtpt` | +0xc8 | +0x39d0 | +0x4540 | 7 + 3 |
| `pmc` | +0xe8 | +0x39f0 | +0x4560 | 6 + 2 |
| `tde` | +0xf4 | +0x39fc | +0x456c | 7 + 3 |
| `tce` | +0xf5 | +0x39fd | +0x456d | 9 + 5 |

Every field is also copied by the clone `0x55ea030` (#6091) and stored by the action dispatchers `0x538cd30` (A) and `0x5397b50` (B).

## Evidence 2: `aci` is the abci digest interval

- A step `0x5a07ec0`: `mov rcx, [rsi+0x39c8]` (`0x5a07f85`), then `div rcx` (`0x5a07f9d`) on the height in `r15`, branching on a zero remainder. B step `0x5a08720` does the same with `+0x4538` (`0x5a087e5`, `0x5a087fd`). This is the "height % box `+0x39c8`" cadence #6023 found, so `aci` is that interval. #6099 found the decoder replaces 0 with 1000.
- The same `height % aci` shape, next to the freeze-height checks at `+0x10e8`/`+0x10f0`, is in the slow step wrapper `0x59ec200` (`0x59ec6a2`, `0x59ecf6b`), the `visor_abci_state` writer `0x5443930` (`0x5443d92`), `0x5a6c8f0` (`0x5a6c918`) and the catch-up step `0x2d25620` (`0x2d257bc`).
- Stores: dispatcher A `0x539337c`, dispatcher B `0x539e19c` (the #5970 setter, which requires `10000 % value == 0`).

## Evidence 3: `tce` and `tde` gate four handlers

`0x57c9f60`, `0x57ca550` (layout A) and `0x57caa40`, `0x57caf30` (layout B) all start the same way (`0x57c9f60` shown):

- `cmp byte [rcx+0x39fd], 0` (`tce`). Clear: return error tag `0xdd` (`0x57c9f9c`).
- Set: take the u64 at argument `+0x48`; `lea r8, [rax-0x2761]`, `cmp r8, -0x275c`, `jae` ok. That accepts exactly 5..=10080; anything else returns error tag `0xd1` with the value (`0x57c9f8e`).
- Later `cmp byte [rax+0x39fc], 0` (`tde`). Clear: error tag `0xdc` (`0x57ca419`).

10080 is the number of minutes in 7 days; reading the argument as minutes is an inference.

## Evidence 4: `pmc` is a date-time with an epoch "unset" value

- Begin_block A `0x54b66b0` stores dword 0 at `+0x39f8` and qword `0xf6401a` at `+0x39f0` (`0x54bfe3c`, `0x54bfe47`).
- It reads the three dwords at `+0x39f0` (`0x54c018d`) and skips the next block when they equal `(0xf6401a, 0, 0)` (`xor edx, 0xf6401a` at `0x54c01a1`).
- `0xf6401a` decodes in chrono's NaiveDate packing (`year << 13 | ordinal << 4 | flags`) as 1970-01-01. So the unset value is the Unix epoch date.
- When set, it adds f64 600.0 s (`0x459568`) through the seconds, time-of-day and date helpers of #5861 (slots `0x64e0f70`, `0x64e0f78`, `0x64e0aa0`).

## Evidence 5: `mtpt`

Stored by the dispatchers A `0x539247f` and B `0x539d29f` after `value < 0x0ccccccccccccccc` (`0x5392468`). Read at `0x5aedd60` (A) and `0x5af2044` (A), copied into a stack record that is passed on. No compare against 1000 was found.

## Implementation and comparison

The tool pins 28 instruction byte runs, the 600.0 constant and the epoch decode, then recomputes the census (11 tests; 8 mutate one byte of a copied image and expect rejection).

## Results and limitations

- Result: `aci` is the digest/periodic interval; `tce` and `tde` are feature gates with error tags 0xdd and 0xdc and a 5..=10080 range check; `pmc` is a date-time whose unset value is 1970-01-01 and which begin_block extends by 600 s.
- Limits: the census covers one operand shape only (no SIB, no `rsp`); what `mtpt` controls; where the `pmc` deadline goes after the date addition; the action names behind the dispatcher stores; the copies at `0x22e56a0`, `0x22e5c90`, `0x22e81c0`, `0x2753b90`, `0x2bdf8f0` are listed but not described.
- Next lead: where the begin_block `pmc` + 600 s deadline is compared, and what the `mtpt` stack record feeds (`0x5a1e320`).
