# RE-012 — Node #115 critical-message date/time format argument

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [date/time display packet](../RE-012-date-time-display-115/) establishes the adapter. The [repeat-throttle packet](../RE-001-node115-critical-message-repeat-throttle/) establishes the enclosing handler and its earlier gate.

At `0x1509e35` the handler formats a first value into a three-word region at stack +0x120. The format entry in R14 comes from slot `0x64df6e8 -> 0x141e3a0`. The handler then reuses that same entry for a second call at `0x1509e8e`. This call uses a new template at `0x431560`, a result region at +0x70, and three argument records at +0x20, +0x30 and +0x40.

The middle argument pairs the pointer retained in R15 with `0x64e0998 -> 0x156d7f0`, the date/time display adapter. The last argument pairs the first result region with its formatter. At the selected later call at `0x1509f76`, the handler passes the original R15 pointer in RDX, and two words from the second format result in RCX and R8. This connects the same date/time input and its containing text result to one downstream handoff.

The selected template is six bytes, `c0 c0 01 20 c0 00`. Under the [established template rules](../RE-012-generated-name-115/), this places a single space after the timestamp argument. Neighboring handler flags and the downstream consumer's effects remain outside this packet. Run `PYTHONPATH=tools python3 research/work-items/RE-012-node115-critical-message-time-argument/verify.py` from the repository root.
