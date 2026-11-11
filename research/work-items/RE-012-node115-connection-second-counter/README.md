# RE-012: node 115 selected connection second counter

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. [#5112](https://github.com/lalalune/hyperliquid-source/pull/5112) establishes the selected first count comparison and explicitly leaves its intermediate `al=3` short of a final policy. This packet traces that branch through the input-flag dispatch and, when selected, a second counter. [#5076](https://github.com/lalalune/hyperliquid-source/pull/5076) and [#5079](https://github.com/lalalune/hyperliquid-source/pull/5079) establish separate request-side uses of the same counter and time-bucket helpers; they are credited, not re-derived here.

## Selected normal continuation

Let N be the result of `0x4fabf60` and T the stable threshold from #5112. Assume the selected N<T path, normal helper and lock returns, valid storage, no intervening aliases, and the caller's input `edx` low byte F is either 0 or 1. The path sets intermediate `al=3` and enters `0x5a62e6a`. With F=0 it returns `al=3` without taking this second-counter route. With F=1 it acquires the selected byte lock, constructs a local object whose first byte is zero and next four bytes are the original `esi` dword, and performs the selected time-bucket preparation.

The second path calls `0x5617370` on the counter region at owner `+0x18`, then passes that same region and the local object to `0x59db3a0`, with `edx=1` and `ecx=1`. After the counter helper returns, the caller saves its result, releases the byte lock, restores the result and XORs its low byte with 3. Thus, if the helper returns low byte R and all selected calls return normally, the selected final `al` is `R xor 3`; for R=0/1 the respective bytes are 3/2. The release slow path rejoins before this transformation. The packet makes no claim that arbitrary helper returns are only 0 or 1, or that the local object is a fully initialized source-level key.

The input flag's source meaning, time conversion units, counter callback behavior, concurrent execution, errors/unwinds, other first-count outcomes and whether the resulting byte admits a network connection remain open. The proof does not imply object identity with the different request-side uses in the cited PRs.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-connection-second-counter/verify.py` authenticates the target and three complete FDE bodies, selected instructions, helper call targets and corruption controls; simple arithmetic examples do not execute or emulate the target.
