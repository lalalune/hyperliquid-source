# staking: tokenDelegate and CValidator entry paths in node #94

This packet shows how node #94 decides the terms of a delegation before the core runs, so a reconstruction can write the entry code from bytes: `tokenDelegate` builds a three way mode row whose value word is the self delegation floor, and that floor is `self_delegation_requirement` for a foundation validator or in the first year after the row time at `validator_to_state`, and 0 after that; CValidator register swallows a failed first self delegation, and only the third code copy writes a delegate ledger record.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/exchange/handlers/33_token_delegate.rs` and `l1/chain_ext.rs` were read as leads only; the table below lists where the bytes differ.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Names not found in rodata are marked inference. Unresolved items are under limitations.
- Scope included and excluded: included are the whole functions `0x1e5fa70`, `0x46774d0`, `0x4677420` (wrapper), `0x2757fe0`, `0x4d80870`, `0x4d80bc0` (gate), `0x2768ff0`, `0x4d9e0d0`, `0x4d9dcd0` (CValidator host), `0x275aa60`, `0x4d85ff0`, `0x39963e0`, `0x3996230`, `0x4856ca0`, the set entry points `0x33de710`, `0x33de620`, the set lookups `0x284bb50`, `0x49277e0`, and the init closures of the five static sets. Wrappers and hosts appear elsewhere only as dispatch rows (RE-010), the shared lookup `0x284bb50` as a helper of the liquidate packet, and `0x33de620` as a stub of the cSigner packet, which left the set content open; this packet answers that open item. Excluded, and stubs here: the core `0x398dc90` and its `0x3c0e8b0`, which #46 lists, the profile gate `0x3994f20` of #597, the drops, `0x27add60`, `0x1459ca0`, `0x33bc0a0`, `0x151cba0`, `0x3987cb0` and the sink `0x47ed710`.

## Reproduce

From the repository root:

```
python3 tools/staking_delegate_entry.py --out research/work-items/staking-delegate-entry-94
python3 -m unittest tests.test_staking_delegate_entry
```

The tool takes about 2 minutes with 4 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed: an interpreter inside the tool evaluates its bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `callers.tsv`, `constants.tsv`, `status-text.tsv`, `foundation-lists.tsv`, `chain-arms.tsv`, `list-sites.tsv`, `key-texts.tsv`, `copy-compare.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. Slots come from `.rela.dyn`. `E` is the Exchange pointer. Field offsets below are for the first two copies; the third adds `0xa80` to every staking field, so `S = E + 0x8f8` becomes `E + 0x1378`.

### Path

```
0x2759240 dispatch
  0x1e5fa70 wrapper      wei >= 0xccc...c: outer 0xe, status 0x13f, wei at +0x10
    0x2757fe0 gate       builds (tag, value, wei, E+0x60 time, user, validator, chain byte)
      0x33de710, 0x33de620, 0x284bb50   foundation test
      0x1459ca0          row time + 31557600.0 s
      slot 0x5774d20 -> 0x398dc90 core
      0x4856ca0          delegate record, third copy only
  0x2768ff0 host         register, profile change, unregister
    0x39963e0            user_states word
    0x3994f20            profile gate
    0x275aa60            first self delegation, third copy calls the gate instead
  0x3996230              long term lock stamp, cUserModify arm at 0x275a318
```

### Mode row

Wrapper `rsi` action: `+0x20` wei, `+0x30` validator, `+0x45` mode byte. Status text is the Display table `0x59a8d0` (`status-text.tsv`). Gate order, first failure wins:

| Step | Test | Result |
|---|---|---|
| 1 | dword `E+0x80 != 1` | `0xfb` Native token does not exist |
| 2 | wei 0 | `0x32` |
| 3 | mode 0 | row `(2, 0)` |
| 4 | mode above 1 | row `(1, mode)` |
| 5 | mode 1, user differs from validator | row `(0, 0)` |
| 6 | mode 1, same address, no row in `E+0xb70` | `0x91` Unknown validator |
| 7 | same, in the foundation validator set | row `(0, F)`, no time add |
| 8 | same, row time + one year below block time | row `(0, 0)` |
| 9 | same, otherwise | row `(0, F)` |

`F` is `self_delegation_requirement`, the word at `E+0xb38`, and `E+0xb70` is `validator_to_state`: the serializer rows `0x399078d`, `0x3990794` and `0x39907eb` bind `S+0x240` and `S+0x278` to those keys (`constants.tsv`). The time compare is signed on the first word and unsigned on the next two, and an equal time keeps `F`. The row time is the first 12 bytes of a 28 byte value, keyed by address, node keys `+8`, values `+0xe4`, length `+0x21a`, edges `+0x220`. Only a same address exit reads the row, and a mode 1 row for any other delegator does not look at the validator at all.

The core reads what the gate built. Rows `0x3c0ec6b..0x3c0ecce` of `0x3c0e8b0`, read but not evaluated here, take tag 0 and give `0xff` while the 12 bytes at `user_states` row `+8` are above block time, then give `0x130` when the saturating `balance - wei` is below the value word. So a zero value allows a full exit and `F` refuses one.

### Foundation sets

`foundation-lists.tsv` holds every address, read from the `movups` source and the `movl` immediate of the closures. The cell of each `LazyLock` comes from `.rela.dyn` and the arms from the jump table `0x58a6b4` (`chain-arms.tsv`).

| Set | Cell | Rule |
|---|---|---|
| chain 1 | `0x57861d8` | 4 literals |
| chain 2 | `0x57861f8` | 4 literals |
| chain 3 | `0x5786218` | 4 literals |
| chain 3 validators | `0x5786238` | copy of cell `0x5786218` plus `0x66be52ec79f829cc88e5778a255e2cb9492798fd` |
| chain 3 signers | `0x5786258` | same 4 literals plus `0x5795ab6e71ecbefa255fc4728cc34893ba992d44`, built in full |

`0x33de620` takes chain 1, 2 or 3 and panics with `invalid chain` on 0. `0x33de710` differs only on chain 3, where it gives cell `0x5786238`. That settles the open point of the cSigner packet: the two chain 3 statics are the four shared keys with and without the fifth validator key. `list-sites.tsv` shows who names each cell: `0x5786258` has 2 rows, both in `0x2275a10`, and `0x5786238` is read by `0x227bd40`, `0x398faa0`, `0x3c10fa0`, `0x3c11bd0` and `0x33de710`.

### CValidator host

Action word 0 selects the arm: `0x8000000000000001` is refused with `0x8e` at once, any other value with the top bit set takes the change arm, and the rest take the register arm. Order:

1. `E+0xb88` byte 0: the user must be in the set at `E+0xa18`, else `0x94`.
2. Change arm: byte `+0x5e`, unless 2, must have bit 0 equal to "chain byte is 0", else `0x8e`. Register arm: bit 0 of byte `+0x4c` has the same rule.
3. Register arm: wei at `+0x58` at or above the limit gives `0x13f`. If wei and `F` are not both 0: byte `+0x51` set gives `0xfd`, byte `E+0x80` 0 gives `0xfb`, wei below `F` gives `0x130`, `user_states` word below wei gives `0xfc`.
4. `0x3994f20` runs on a clone. A refusal is copied out whole.
5. Change arm or wei 0: `0x186`. Otherwise `0x275aa60(E, user, user, wei)`, and any failure goes to the drop and the host still gives `0x186`.

So a register that passes the profile gate reports success even when its self delegation fails. Step 3 tests one byte of the word at `E+0x80` and `0x275aa60` tests the dword, so a word of `0x101` passes step 3 and then loses the delegation with no error.

### Lock stamp

`0x3996230` returns when action byte `+0x29` is 0. Otherwise it writes block time plus seconds into `user_states` row `+8` for the user, inserting a row if there is none. Seconds come from the table `0x207150`: 300.0 on chain 1 and 2, 31557600.0 on any other byte. This is the word the core tests for `0xff`.

### Delegate record

`0x4d80bc0` adds one call after core success: `0x4856ca0(E+0x5b8, row)`. It does nothing when word `E+0xdc0` is `i64::MIN`. Otherwise it reads the wall clock through `0x151cba0`, takes the block hash through `0x3987cb0` when dword `E+0` is 1 and 32 zero bytes when not, and calls `0x47ed710` with a record: kind `0x8000000000000001`, `f64(wei) / 10^d` with `d` from token row `+0x49`, user, validator, byte `mode != 0`, and block time at `+0xe8`. Token id at or above the count panics. Register in the third copy goes through this gate with mode 0, so it writes one too. The first two copies write nothing (`copy-compare.tsv`).

## Implementation and comparison

not yet implemented

Reference comparison, `l1/exchange/handlers/33_token_delegate.rs`:

| Point | Reference | Bytes |
|---|---|---|
| Foundation in a self exit | skips the lock test, keeps the floor | keeps the floor for ever, no time test |
| Other validators in a self exit | unlock time before now, else `255` | one year test only sets the floor to 0 or `F`, no refusal in the gate |
| Floor test | `remaining != 0 && remaining < req` | no exception for 0, and the value is 0 after the year |
| Missing validator row | `145` for every action | only for a same address exit in the gate |
| `undelegations_blocked` | a bool on the lot | block time against 12 bytes stamped by `0x3996230` |
| Modes | bool | three row tags, tag 1 only for a byte above 1 |

`l1/chain_ext.rs` matches all listed addresses.

## Results and limitations

- 59 unit tests pass with no binutils on PATH. Negative controls: digest, bounds, spoiled constants, a spoiled list byte, a changed list, a flipped condition, a wrong rule, an unknown case field.
- 1451 named and 300 generated cases on all three copies: 0 mismatches between the evaluator and the separately written rule list, on status, output bytes, event order, stub arguments and state bytes.
- 711 byte edits on reached rows: 692 killed, 19 survived, 0 open. Survivors by class:
  - 10: failure bytes of the register self delegation: only the tag reaches the drop stub
  - 4: success tag test: the failure arm forwards the same 0x186 word, so both arms give one result
  - 3: second wei limit in the host: the first limit at 0x2769077 already passed, so this row cannot refuse
  - 2: found pointer of the set lookup: the callers test it against zero only
- Unreached: 9 of 1922 rows: the refusal arm of the second wei limit in each of the three hosts, which cannot fire after the first limit.
- Stubs: the core, profile gate, drops, clone, `chrono` add, wall clock, block hash and sink. The add stub returns a value set by the case, so a `chrono` overflow panic is not covered, and the case dates are not real calendar values. The closures and the `Once` runtime are parsed or stubbed, not evaluated.
- The core rows quoted under Mode row were read and not run.
- Inference: register, change and unregister as arm names (reference label and rodata `enum CValidatorAction`); row time as `register_time` and the sets as foundation sets (rodata order in `key-texts.tsv` and reference terms). Bytes `+0x4c` and `+0x5e` as the node address tag, `+0x51` as `delegations_disabled`, `+0x29` as `extend_long_term_staking`, and chain 3 as mainnet.
- Unknown: who can produce a mode byte above 1, since the decoder is not read here; the record kind name; what the third copy's Exchange type is.

## Next question

Which decoder writes the mode byte at action `+0x45`, and is row tag 1 reachable from any signed action?
