# RE-008: node #115 begin_block A per-key action `0x5582180` and its record gates (stage 96)

- Component ID: abci. Question: stage 95 (#6205) found that the begin_block A cursor loop collects 20-byte keys whose record byte `+0x3c` is 4, whose box byte `+0x7b8` bit 0 is clear and for which slot `0x64e7190` returns true, and passes each key to `0x5582180`. What does that call do, and what is the slot check?
- Target: node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked by the tool).
- Source commit: `a8616af94` (origin/main). Continues open PRs #6164 and #6205; does not depend on their files.
- Claim status: instruction bytes, offsets, relocations, Location records, FDE extents and call censuses are observations. "Clearinghouse", "ring", "counter", "mode" and "flag" are inferred labels from strides, Locations and branch shapes. The binary was not executed.
- Field names come from #6097 (Locus): `blp` +0x670..+0x7c0, `cls` +0x7c0, `ctr` +0xa78..+0xb78.

## Reproduce

```
python3 tools/begin_block_key_action_115.py --check
python3 -m unittest tests.test_begin_block_key_action_115
```

The tool reads the ELF only. The four `*.objdump.txt` files (GNU objdump 2.42) are for review; the tool does not read them.

## Evidence 1: four callers and their arguments

`0x5582180` (FDE `0x5582180..0x5585283`) has exactly four direct calls. Arguments: `rdi` out (a Vec of 8-byte items), `rsi` box, `rdx` pointer to the 20-byte key, `ecx` flag, `r8` mode, `r9` one item.

| Call | In | ecx | r8 |
|---|---|---|---|
| `0x54c0345` | begin_block A `0x54b66b0` | 0 | 1 |
| `0x5588e32` | `0x5588d90` | 0 | 1 or 0 (r9 = r15) |
| `0x558b7c6` | `0x558b730` | 1 | r15 |
| `0x558b9a0` | `0x558b730` | 1 | r15 |

## Evidence 2: two input modes and the clearinghouse read

- `r8 == 1` (`0x55821b4`): walk box `+0x6c8` (tag, `0x8000000000000000` = one form), `+0x6d0` ptr, `+0x6d8` head, `+0x6e0` len, items `0xb8` bytes (`imul … 0xb8` at `0x5582279`), all inside Locus `blp`.
- Otherwise: one 8-byte item boxed from `r9` (`0x55821f6..0x5582230`).
- For each element of box `+0x7c8` (len `+0x7d0`, Locus `cls`, stride `0x510`) it copies the element's `+0x50` word into a new array (`0x5582390`, `0x558239b`, `0x55823a7`, `[rsi]`).
- Panic Locations loaded in the function include `l1/src/dex_registry/clearinghouses.rs:11:29` (three loads at `0x5584dff`, `0x5584e36`, `0x5584e6d`), `l1/src/qtys/mod.rs:847:1`, `l1/src/qtys/impl_ntl.rs:70:1` and `l1/src/qtys/impl_wei.rs:6:1`. Inference: `cls` is the clearinghouse list.

## Evidence 3: the one box store

`0x5583256..0x5583288`: when `[rsp+0x58]` (r8) is non-zero and the local flag byte `[rsp+0x28]` is set, box `+0xab0` (Locus `ctr`) is incremented with saturation (`inc` / `cmove -1`). It is the only store through the box pointer in the function.

## Evidence 4: begin_block A discards the result

After the call (`0x54c034a..0x54c036e`) begin_block A frees the returned Vec (cap `[rsp+0x60]`, ptr `[rsp+0x68]`, size `cap*8`) unless the cap is `0x8000000000000000` or 0, and never reads it.

## Evidence 5: the slot gate `0x3693030`

Slot `0x64e7190` is relocated to `0x3693030`, which has no direct calls. It returns true when:

- ring/Vec form: any 0x28-byte element has a non-zero `+0x10` word (`0x3693150`, `mov al,1` at `0x369315a`);
- map form: any value has a non-zero `+0x8` word (`0x3693180`, via iterator `0x37c9030`);

and false otherwise (`0x36931d6`). Inference: "the key's record holds at least one non-empty entry".

## Results and limitations

- Result: per collected key, begin_block A runs `0x5582180` in mode 1 over Locus `blp`'s 0xb8-byte ring, reads one word per clearinghouse, may bump the saturating counter box `+0xab0`, and throws the returned Vec away.
- Limits: what sets the local flag `[rsp+0x28]`; the meaning of record byte `+0x3c` value 4 (values only, no names); what `0x4ef4480` returns for the record lookup; the body between the clearinghouse read and the counter (135 calls in the FDE are not mapped); what box `+0x7b8` bit 0 means; the three other callers' contexts.
- Next lead: the local flag `[rsp+0x28]` writers inside `0x5582180`, which decide when the counter moves.
