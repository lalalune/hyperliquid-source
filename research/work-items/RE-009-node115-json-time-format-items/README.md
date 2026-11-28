# RE-009 #115 JSON checkpoint time format items

The quoted JSON time reader used by `exchange.locus.ctx.time` and `prev_time` calls `0x472e8c0`. This packet identifies the actual format items passed to the parser and the conditions for returning its 12-byte time value. The [JSON context packet](../RE-009-node115-json-context-clocks/README.md) established the field mapping and stopped at this conversion.

At `0x472e985` and `0x472e98c`, the adapter passes the half-open item range `0x6405668..0x6405818` to `0x1620be0`. The range holds 18 records of 24 bytes each. Resolving the literal pointers through the relative relocations yields this item order:

```text
Year space "-" Month space "-" Day space "T"
Hour space ":" Minute space ":" Second Nanosecond space
```

Names and item behavior come from the independently mapped [format-item interpreter](../foundation-chrono-parse-internal-115/README.md). The entries shown as `space` are trim items with zero-length text. The fraction uses the fixed Nanosecond kind, with the optional dot-and-digits behavior of that interpreter. The array contains no timezone item. These observations explain why the usual date and time separated by uppercase `T` is appropriate for the selected JSON fixture path.

The adapter requires a non-null parse remainder pointer and zero remainder length. It then calls relative slot `0x64e1260` → `0x1627e60` with the parsed fields and zero in EDX. On the selected successful result, it returns the resulting qword and dword at output `+4` and `+0xc`. The proof stops at the constructor's output and does not claim calendar or leap-second conversion equivalence, coverage of other time sites, or a matched replay root.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-json-time-format-items/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
