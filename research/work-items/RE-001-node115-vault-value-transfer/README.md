# RE-001: trace the node 115 vault post-guard value transfer

Partial progress for [#3925](https://github.com/lalalune/hyperliquid-source/issues/3925).
This extends the existing entry-guard evidence through a selected admitted
amount path to keyed field writes and a downstream continuation. The issue and
all full-component gates remain open.

## Target and question

- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Original node #115 ELF: 105,896,032 bytes; SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates are ELF virtual addresses.
- Question: after the previously recorded entry guards, which amount and
  address arguments reach the debit/credit helpers, and where do those helpers
  actually store the changed value?

`RE-001-node115-vault-entry-guards` / [#2220](https://github.com/lalalune/hyperliquid-source/pull/2220)
stops at the subsequent helper boundary. Earlier node #94 work
([#873](https://github.com/lalalune/hyperliquid-source/pull/873),
[#967](https://github.com/lalalune/hyperliquid-source/pull/967)) leaves helper
internals positional or stubbed. This packet does not transplant those bodies
or assume that an address in another release has the same meaning.

## Selected admitted path

The owner is `0x44ae810..0x44af2e1`. It preserves the incoming amount from RCX
in R13, the source key from RDX, and the vault object from RSI. In the selected
availability branch, `0x44aec00` calls `0x446bdd0` through relocation slot
`0x64e5078`. A negative amount takes the unwrap/panic path; the unsigned
comparison at `0x44aec0f` permits equality and enters `0x44aed88` only when the
available value is at least the nonnegative amount.

| Order on normal helper return | Key/value evidence |
|---|---|
| Debit helper call `0x44aed93` | Slot `0x64e7170` resolves to `0x447db40`; arguments are the supplied context, original source key, and preserved amount. |
| Context adjustment | `0x44aeda3..0x44aedac` subtracts that amount from context+0x4a8 and stores the result. Signed overflow takes the observed saturation/reporting branch. |
| Credit helper call `0x44aeddd` | Calls `0x4472ea0` with the same context/amount and the key copied from vault-object+0x8c. |
| Context adjustment | `0x44aedec..0x44aedf5` adds the amount to context+0x4a8 and stores it, with its own signed-overflow handling. This is not a claim that all intermediate effects cancel. |
| Downstream handoff | `0x44aee4c` calls `0x44ad9e0`. Its complete weighting/share behavior is outside this packet. |

Both child helpers reject a negative incoming RDX and use the observed
`0x4717440` / `0x3ee6740` / `0x4717ed0` key/entry path. The selected resolved
entry pointer is saved across further bookkeeping. The debit performs
`entry[+0x48] - amount` and stores at `0x447dd6d`; the credit performs
`entry[+0x48] + amount` and stores at `0x44730cd`. Their overflow continuations
select a signed saturated result before returning to those stores.

The retained later owner window also records unsigned +0x8 and signed +0x10
updates to a selected per-address record, supplied time-field writes, and the
result projection. These observations do not identify complete share-minting
or persistence semantics.

## Evidence and reproduction

`records.json` retains **13 windows / 1,818 bytes / 397 instructions**, with
enclosing FDE bounds and hashes. Only these windows are the validated semantic
scope; decoding a larger enclosing FDE is used to establish boundaries.
There are 32 explicit checks and 11 in-memory controls: reversed amount/limit
branches, a debit-to-credit relocation swap, changed key/context offsets,
changed call targets, swapped arithmetic operations and wrong keyed store
offsets. Controls run the fact checks without the global digest/window checks,
so their rejection does not merely reflect a changed whole-file hash.

Use an existing Python environment with Capstone **5.0.7** and the hydrated
artifact. The observed run used Python **3.14.7**. Existing repository
`RE-001-node115-registry-row-labels/verify.py` supplies ELF/FDE parsing; no new
dependencies are downloaded.

```sh
python3 research/work-items/RE-001-node115-vault-value-transfer/verify.py
```

Expected: 13 windows, 1,818 bytes, 397 instructions, 32 facts and 11 rejected
corruptions. `--target PATH` accepts another copy only if its digest matches.
`verification.json` retains the observed output. No captured instructions are
executed or emulated; no chain, wallet, signing or live financial state is used.

## Premises and remaining work

The interpretation assumes valid native layouts, valid entry collections,
successful delegated lookup/insertion and normal helper return. The complete
availability calculation and its transitive helpers are not reconstructed.
The entry guards remain a prerequisite, not a newly proved authorization model.
The selected helper stores can occur before later calls; atomicity, rollback,
interruption safety and durable persistence are not established. Full deposit
wire identity, units across the entire path, share minting and complete failure
behavior remain open. This is independently authored static research, not
copied inferred source or reconstructed runtime code; imported rights remain
unchanged.
