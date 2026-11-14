# RE-008: node #115 digest quorum store (63rd stage): how a per-height value is resolved

- Component ID: abci. Question: #6049 found that the entry builder `0x53779c0` returns None while a per-height value in store `+0x18` has byte `+0x20` set, and otherwise uses the 32-byte key at `+0x21`. It left open who clears that byte and how the key is chosen.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6048 and #6049 and does not depend on their files.
- Claim status: instruction bytes, offsets, constants and call censuses are observations. "Pending", "resolved", "votes", "stake", "voters" and "two-thirds" are inferred labels from the control flow, the arithmetic and the 32-byte keys. The binary was not executed.
- Scope included: the walker `0x5374b70` (its skip, its check call and its resolution write), the check `0x36c7f70` (absent key and the predicate call), the predicate `0x422e0f0` in full, the return values of `0x4351520`. Scope excluded: the bodies of the map walkers `0x4e18e60`/`0x513cef0`, the collectors `0x53485b0`/`0x5349140`, `0x3bcb550`, `0x4551810`, the 12 other callers of `0x36c7f70`, the source of the count used by the second gate, and the writers that add votes to store `+0x18`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/digest_quorum_votes_115.py --check
python3 -m unittest tests.test_digest_quorum_votes_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the walker runs once per store insert

`0x5374b70` (FDE `0x5374b70..0x5375893`) has one direct call, `0x5afa5f4`, in the store insert `0x5afa5d0` (#6048). It walks the map at store `+0x18` through `0x4e18e60` and skips a value when `cmp byte [value+0x20], 0` is equal (`0x5374d59`, `je` at `0x5374d5d`). So only values with byte `+0x20` set are visited. Inference: `+0x20` set means "pending".

For a pending value it walks the inner map. Inner entries are 0x60 bytes (`lea r8, [rsi+rsi*2]` then `shl 5` at `0x5374dcc`; next entry `rbp+0x60` at `0x5374eba`): a 32-byte key at `+0x0` and a collection of 0x68-byte items at `+0x20` (`0x5374ec6`, `imul rdi, rcx, 0x68` at `0x5374f71`).

## Evidence 2: per inner entry, a stake check

The walker collects the items (`0x53485b0`, `0x5374fc5`) and calls `0x36c7f70` (`0x5374fd8`) with `rdi` = the insert's third argument, `rsi` = that argument's `+0x58` value (`0x5374c9c`) and `rdx` = the collected set. A false result (`test r14b`, `je` at `0x5374feb`) moves to the next inner entry.

`0x36c7f70` looks `rsi` up in the map at `rdi`. When it is absent it stores error tag `0x9b` (`0x36c80a3`), calls `0x36dae30` and returns 0. Otherwise it returns `0x422e0f0(...)` (`0x36c82e4`, vtable `0x6468cb0`).

## Evidence 3: the predicate is a strict two-thirds compare

`0x422e0f0` (FDE `0x422e0f0..0x422e273`, one direct call):

- calls `0x4351520` (`0x422e100`). That function adds looked-up u64 weights (`add r15, [r12]` at `0x4351564`) and returns tag 1 with the sum (`0x43516a7`, `0x43516b0`), or tag 0 on overflow (`0x435156d`). Call the sum S;
- adds u64 `+0x20` of each 0x28-byte item into `r12` (`0x422e160`, `0x422e221`);
- returns `tag == 1 && 2*r12 < 3*S` as a 128-bit unsigned compare: `add r12, r12` with the carry in `rcx`, `mov edx, 3`, `mul rdx`, `cmp r12, rax`, `sbb rcx, rdx`, `setb al` (`0x422e23d..0x422e25e`).

The tool checks the formula against samples: S=201 of 300 is true, S=200 of 300 is false, S=2 of 3 is false, S=3 of 3 is true.

Inference: S is the stake of the signers on the inner entry and `r12` is the total stake, so the check is "signers hold more than two-thirds of the stake". The byte-level formula does not depend on that reading.

## Evidence 4: a second, count-based gate

The walker loads f64 store `+0x38` (`0x5374ca8`). When it is 0 (`ucomisd` at `0x53750f3`, with `bl = 1` preset) the gate passes. Otherwise it converts two u64 values to f64, multiplies one by store `+0x38` (`0x53754f3`) and requires the other to be strictly greater (`ucomisd`, `seta bl` at `0x5375500`). A false `bl` moves to the next inner entry (`0x537555f`). Which counts these are is not mapped.

## Evidence 5: resolution

When both gates pass, the walker writes `mov byte [value+0x20], 0` (`0x5375588`) and copies the inner entry's 32-byte key to value `+0x21..+0x41` (`0x5375596`, `0x537559a`). This is the key #6049's entry builder returns as the quorum digest.

## Census

`0x36c7f70` has 13 direct calls in 13 functions: `0x28a9b70`, `0x28a9db0`, `0x28aa370`, `0x28ab0a0`, `0x3686d90`, `0x36872c0`, `0x3687710`, `0x36879a0`, `0x36c93c0`, `0x5373810`, `0x5373ab0`, `0x5373e40`, `0x5374b70`. Inference: it is a shared stake-quorum check.

## Implementation and comparison

The tool pins 45 instruction byte runs, 6 rel32 calls, one RIP-relative vtable reference and a one-pass call census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing the vote writers (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: a per-height value stays pending (`+0x20` set) until some inner entry's signers pass the two-thirds predicate and the optional count gate; the walker then records that entry's 32-byte key at `+0x21` and clears `+0x20`. Values that never pass stay pending and #6049's builder skips them.
- Limits: the order of inner entries (the first passing entry wins), what map the insert's third argument is and what its `+0x58` key means, the two counts in the second gate, who adds votes to store `+0x18`, the 12 other callers of `0x36c7f70`, and the bodies listed under scope excluded.
- Next lead: the writers that add (key, signer) votes into store `+0x18`.
