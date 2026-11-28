# RE-009 #115 checkpoint clock calendar word

The [time component packet](https://github.com/lalalune/hyperliquid-source/pull/7238) follows the first word of the 12-byte checkpoint clock to the upper return dword of the date helper `0x1627430`. This packet resolves how the helper constructs that dword on the selected calendar year/month/day path.

- The selected branch reads the month and day at parsed-record `+0x44` and `+0x6c` when their presence fields are set.
- It reduces the resolved year modulo 400 and reads a byte from the table at `0x46be3b`. It forms `(month << 9) | (day << 4) | flags`, shifts that value right by three for the lookup index, and reads a signed byte from `0x46c2a8`.
- A zero lookup byte takes the error continuation. Otherwise the helper subtracts eight times that byte from the temporary and ORs in `year << 13`. The selected successful continuation returns the resulting word in the upper half of RAX. The caller shifts it down and puts it at `+0` of the constructed clock. The resulting calendar word identifies the year above bit 12 and the ordinal in bits 4–12.

The verifier compares all 146,097 valid dates in one Gregorian cycle from 2000 through 2399 with Python's calendar. It separately checks lookup entries for February 29 in 2000 and 2100 and for April 31 in 2026. This measures the table-backed packing model with the existing artifact. It does not execute the native parser, model other date representations or claim full restore behavior.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-clock-calendar-pack/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
