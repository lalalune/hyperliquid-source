# RE-004 — Node #115 borrow/lend query argument layout

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet resolves the normal argument handoff from two parsers previously stubbed by [the user reply packet](../RE-004-bole-user-reply-115/) and [the reserve reply packet](../RE-004-bole-reserve-reply-115/). The dual-block packet identified the arities.

| Query | Parser | Standard input bytes relative to the argument slice | Parser result |
| --- | --- | --- | --- |
| User, `0x0811` | `0x3897020` | Address at bytes 12–31, big-endian token at bytes 56–63 | Tag `0x0c`, address at +8, little-endian token at +32 |
| Reserve, `0x0812` | `0x3897200` | Big-endian token at bytes 24–31 | Tag `0x0c`, little-endian token at +8 |

The user parser's two adjacent copies at `0x3897179` and `0x3897181` cover consecutive input bytes without gaps. Both parsers load the final eight bytes of the token word and apply `bswap` before storing the result. Both parser paths record a vector comparison using the constant at `0x454f90` and a scalar check before the transfer. The mapping here applies to standard zero-padded ABI inputs. The recorded early length branches precede the respective word reads. Noncanonical inputs, fallback-helper behavior and other result types remain open.

Run `PYTHONPATH=tools python3 research/work-items/RE-004-node115-bole-query-argument-layout/verify.py` at the repository root. It verifies the selected instruction bytes, FDEs, targets and vector constant, then checks the recovered byte mapping against standard padded encodings. No target code runs.
