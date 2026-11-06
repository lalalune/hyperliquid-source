# RE-009 · Snapshot wide unsigned writer

Node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The parent window tests the high 32 bits and passes the full unsigned word in RSI at `0x25e9d2f` to `0x25ea910`. The helper's normal selected path stores marker CF and byte-swaps the 64-bit value before the payload write. This is the wide branch left open in RE-009-abci-freeze-snapshot-115. Selected growth and failure decisions are described below.

Run `python3 research/work-items/RE-009-node115-snapshot-wide-unsigned/verify.py` from the repository root. Local checks cover 404 bytes, 108 instruction rows, the linked call target and displacement corruption. The 1,071-PR diff index has no entry or internal address hit for this FDE and no hit for the caller site. Live refresh and full pre-submission validation remain pending. No target execution.

## Buffer outcomes

The three observed object words at +0, +8 and +0x10 act as a capacity, byte pointer and used count on this path. With nine or more available bytes, no growth call is needed. The writer stores CF at the original used count, increments it by one, byte-swaps the argument, then stores all eight bytes and increments by eight. The normal result is 2. For an input of 0x0102030405060708 the derived bytes are CF 01 02 03 04 05 06 07 08.

When the buffer initially has no free space, the branch at 0x25ea925 reaches the first growth call at 0x25eaa21. A result tag of 1 returns 0 before writing CF. If the marker has already been written and additional capacity is needed, the growth call at 0x25ea99e can instead return status 1 with the marker and incremented used count left in place. The wrapped length check at 0x25ea964 also returns 1 after the marker. The two calls to 0x231e050 receive requested increments 1 and 8 respectively. The paths after those calls are conditional on their return and capacity effects, and no unwinding behavior or allocation contract is inferred.
