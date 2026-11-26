# RE-001: node115 vault-summary final-query future binding

- Component ID: `info-api` (RE-012)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`
- Claim status: observations below are byte- and relocation-bound; interpretation of the returned fields is unresolved.
- Scope included and excluded: binds the final `small_vault_summaries_get` caller to its async poll vtable and maps that poll future's pending/ready envelope. Does not claim lookup contents, cache consistency, complete response serialization, authorization, scheduler semantics, cancellation, or component completion.

The existing [refresh-trigger packet](../RE-001-node115-vault-summary-refresh-trigger/README.md) proves the caller computes and passes the nonnegative saturating cutoff, cache owner, request record, `small_vault_summaries_get` label and source-location descriptor at `0x29696d3..0x296973e`. It stops before the concrete poll method. This packet closes that specific vtable edge only.

At `0x296973e`, the caller invokes `0x29bb680` with result storage at `rsp+0x60`, a six-word argument record at `rsp`, zero `rdx`/`rcx`, and location descriptor `0x6441b38`. The handler then copies 24 raw bytes from that result area to the outer result. The constructed future's poll slot is `0x6443108`; its `R_X86_64_RELATIVE` relocation resolves to `0x297f560`. The complete poll FDE `0x297f560..0x297f70d` reads its state byte at object+`0x29` and dispatches through the eight-entry signed-relative table at `0x60028c`.

For the normal initial and suspended routes, state 0 enters at `0x297f588`; state 3 resumes at `0x297f5d4`. Both poll the inner future through vtable `0x6442ac0` slot+`0x18`, bound by RELATIVE relocation to `0x2979c10`. The inner poll's source-location and call edge are already covered by [the existing FDE-edge packet](../RE-001-node115-loc-edge-2979c48/README.md); this packet uses only its target address and does not re-claim its body. A pending result is identified by the signed-minimum sentinel at the first output qword; it writes the same sentinel to the outer result and sets state 3. A ready result drops the inner future, copies 24 bytes (16+8) to the outer result, and sets state 1. Other table entries leave this FDE; their target semantics and the language-level cancellation meaning are not inferred.

No query semantics or field meaning is assigned to the 24-byte result. This is a wrapper-level poll envelope only, not evidence of public endpoint serialization.

## Reproduce

Static analysis only; captured target was not executed or emulated. Exact target size: 105,896,032 bytes. GNU binutils 2.47.20260726, Apple LLVM objdump 21.0.0, Capstone 5.0.7, Python 3.14.3, macOS arm64.

```sh
PATH=/opt/homebrew/opt/binutils/bin:$PATH python3 research/work-items/RE-001-node115-vault-query-future-binding/export.py
python3 research/work-items/RE-001-node115-vault-query-future-binding/verify.py --controls
python3 -m unittest tests.test_node115_vault_query_future_binding -v
```

## Evidence

The two independent disassemblers agree on complete byte coverage for the retained poll FDE. `poll.gnu.txt` and `poll.llvm.txt` preserve the raw output; `fdes.gnu.txt` preserves its unwind record. `state-table.json` records the signed-relative entries and resolved targets. `verify.py --controls` rechecks whole-image digest and size, the poll FDE boundary and hash, poll-slot relocations, query label bytes, the state-table targets, sentinel/output/state transitions, and the caller's 24-byte copy against target bytes and prior packet context. `controls.json` records rejection of altered instruction, table, relocation, and label bytes.

- Claim boundary: the caller already constructs the `small_vault_summaries_get` operation; this packet binds its poll method and pending/ready envelope. The result payload and the helper's lookup behavior remain unknown.
- Next question: close the helper's actual read source and async error/cancellation cleanup without conflating scheduler or generic future machinery with the public response.
- No progress gate is requested; issue #3921 remains 0/4 accepted.
