# RE-012: two distinct resume states behind one gossip-path result byte

- Component `node-runtime`; bounded scheduling/continuation question under [issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927).
- Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`. Addresses are linked ELF VAs before load bias.
- Static evidence only: no captured binary or instruction evaluation, clock call, network or runtime state. No component gate, reconstructed implementation or observed service behavior is claimed.

## Question and result

The [greeting packet](../RE-017-abci-greeting-115/README.md) observes `0x2ae0920` as an inner boundary and notes its `0x45` result, while [block-fill evidence](../RE-005-node115-block-fill-writers/README.md) retains its full body for a different input-provenance question. The connection callers in [PR #4345](https://github.com/lalalune/hyperliquid-source/pull/4345) branch on the same result byte before the gossip-reload path. This packet addresses a separate continuation question: does that one external byte uniquely determine the inner saved state?

At entry the owner saves output in `r15`, object in `rbx`, and indexes signed relative table `0x604058` with the object's first byte. The **five checked entries** 0–4 point to `0x2ae094d`, `0x2ae11ae`, `0x2ae11bb`, `0x2ae096d`, and `0x2ae099d`. We do not assert a valid input domain or interpret entries 1 and 2.

- Entry 0 performs the recorded initial field stores and flows into the code also selected directly by entry 3. That code calls `0x2ae0100` and reads its result's first byte. If it equals `0x45`, the owner writes `0x45` to output and writes **3** to the object's first byte via the shared normal return at `0x2ae117f`.
- On a separate selected path, `0x2b782e0` yields first word 3 and the relocation-backed slot `0x64e1358 -> 0x5ce94c0` yields a nonzero low byte. The owner writes 3 through each of two previously prepared pointers, writes `0x45` to output and writes **4** to the object's first byte through the same return.
- On a later entry with first byte 3, the table points back to the `0x2ae0100` call. First byte 4 instead enters `0x2ae099d`, reads object `+0x3b0` and starts a different relative-table dispatch at `0x60406c`. The two saved states therefore do not select the same immediate continuation.
- Separately, if control reaches `0x2ae112e`, it copies the then-current `bpl` byte and selected payload fields to output and sets object state 1. This packet does not assert where every such byte or payload originates, or that all earlier branches reach this site.

The same external `0x45` can thus accompany two different observed internal state stores; treating it alone as a complete resumption state would lose information. This is a conditional static observation, not proof of runtime reachability or a claim that the inner helpers implement any named async contract. Helper side effects, time/TLS behavior, exception cleanup, the full second table and all states outside the five selected entries remain open.

## Evidence and controls

The verifier authenticates three complete indexed FDEs: owner `[0x2ae0920,0x2ae135b)` (2,619 bytes), credited nested call `[0x2ae0100,0x2ae0917)` (2,071), and credited gate target `[0x5ce94c0,0x5ce95b7)` (247). The latter two are hash/boundary context only. All three bodies are decoded with Capstone for instruction boundaries; selected GNU exports retain trailing-whitespace-normalized windows. The 4,937-byte extent measures evidence, not implementation coverage.

```sh
PYTHONPATH=tools python3 research/work-items/RE-012-node115-gossip-poll-resume/verify.py
(cd research/work-items/RE-012-node115-gossip-poll-resume && shasum -a 256 -c MANIFEST.sha256)
```

With Python 3.14.5, Capstone 5.0.7 and GNU objdump 2.42, the static verifier checks the target digest, indexed extents and hashes, 64 exact instruction spans, seven encoded targets, five table entries and one relocation. Five mutations independently change output/state stores or the common return and are rejected below the whole-body hash. The tests check evidence bytes and decoded boundaries, not target execution or behavioral equivalence. Next: resolve the state-4 nested table and its producer's ownership/error paths before attempting a full reconstruction.
