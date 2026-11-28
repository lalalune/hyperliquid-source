# RE-017 · Node #115 bootstrap response rows reach the replay worker

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `c42e4eebf847462db32c934af4140a346ebba310`. Addresses are linked ELF virtual addresses.

## Question

The inclusive range study [RE-014 / #2031](../RE-014-bootstrap-range-rust-115/README.md) describes a bounded request, while the [limit-writer packet](../RE-005-node115-limit-writers/README.md) analyzes the buffer limit producer used by `0x5a6a640`. On the selected completed response, what makes a row available to the replay worker, and what fields are passed from that row?

## Observations

1. **Successful query result.** `0x5a83698` calls `0x5a6a640` with caller output at stack+0x1420. In that helper, the selected reply arm of `0x58606f0` supplies three qwords starting at its result+0x10. They pass through stack+0x260 to output+0x18/+0x20/+0x28, while `0x5a6bcb5` chooses the outer byte tag `0x44`. In the caller, the selected success continuation checks outer tag `0x44`, qword +8 equal to 3, and qword +0x10 unequal to 1. The branch at `0x5a83c1d` examines the preserved +0x28 count, and on a nonempty response first and last rows supply display values. The nearby diagnostic bytes include `client blocks first=`. These observations identify the selected completed response arm, with prior protocol and normal local result prerequisites assumed.
2. **Local row cursor.** The selected continuation preserves the vector words through root stack moves, including the pointer and count through stack+0x3b0/+0x3b8. At `0x5a841db` the resulting `0x44` tag permits copying the vector words into F+0x298/+0x2a0/+0x2a8. The caller takes data start from F+0x2a0 and count from F+0x2a8 to calculate exclusive end `start + 16 * count`, then writes start to F+0x230 and end to F+0x240.
3. **Worker call.** `0x5a82cd5` compares the cursor and end. Equality skips the row and worker call. Otherwise `0x5a82ce3` advances the saved cursor by 16, and the code loads the two qwords at the current row's +0/+8 without reordering them. At `0x5a82d0a..0x5a82d18`, it places the pointer from F+0x268 followed by the two row words in the worker input at F+0x2d0. The selected direct call at `0x5a82d3c` passes that address to `0x5a897e0`.

A fixture can preserve the successful response's row order and test exhaustion at the exclusive endpoint. The scope ends at the worker call. When the input is fetched from a real peer, its complete decode/validation, any other successful variants, worker effects, retry or empty-response routing, Block execution and expected state roots require further evidence. This packet does not treat a shape-checked input as proof of execution or root equivalence.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-bootstrap-response-row-handoff/verify.py
```

The [offline output](offline-log.txt) records the digest and checks. The [instruction spans](windows.txt) and verifier establish the selected result fields, completed-response gates and exact address projection into the worker input. Synthetic valid two-row and exhausted-cursor controls preserve pointer order and distinguish one-step versus zero- or two-step advancement. The captured executable is read as ELF data.
