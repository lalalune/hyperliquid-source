# Node 115 HIP-3 common identity lookup

This packet resolves the helper behind the identity lookup at the start of the
common HIP-3 action preparation routine. The parent
[disabled-state writer packet](../RE-007-node115-hip3-disabled-state-writer/README.md)
already pins the callsite, the returned record byte at `+0x3c`, and the
following state-byte predicates. This supplement traces the lookup helper and
its general hash-table branch.

The downstream non-owner selector membership helper at `0x469e170` is covered
separately by merged [PR #7109](https://github.com/lalalune/hyperliquid-source/pull/7109).
The two lookups are distinct. This packet does not claim cryptographic
authentication, complete role semantics, or a component gate.

## Target and reproduction

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Verifier environment: Python 3.14.3 and Capstone 5.0.7; manual disassembly used GNU binutils 2.47.20260726.
- The verifier checks full FDEs for the lookup, hash, and probe helpers.

```sh
python3 research/work-items/RE-007-node115-hip3-disable-authz-path/verify.py \
  --target artifacts/node/115/hl-node
```

The verifier reads ELF bytes only. It checks the target digest, FDE bounds,
instruction boundaries, selected instruction bytes, and one-byte corruption
controls. It never executes the node.

## Observed behavior

At `0x29467e0`, the caller copies the 20-byte identity argument and passes the
state pointer and copy to `0x2a8a770`. The returned pointer's byte at `+0x3c`
feeds the already-pinned local predicate: class `4` is checked against
`S+0x7b8`; other classes below `3` are checked against `S+0x7b9`. The values'
application names are unknown.

`0x2a8a770` reads a count at `S+0x978` and the associated storage at
`S+0x970`:

- When the count is `1`, it compares the input key as 16 bytes plus 4 bytes
  against an entry at offsets `+0x48` and `+0x58`.
- Otherwise, it passes the 20-byte key and values loaded from state fields
  `S+0x9a0` and `S+0x9a8` to `0x2b6e540`. That routine uses its first two
  arguments to initialize hash state and passes the exact length `0x14` with
  the key to `0x2b41610`. The resulting hash and key
  go to `0x26fe6d0`.
- `0x26fe6d0` uses high hash bits to select control-byte candidates, then
  compares each candidate's stored key as 16 bytes plus 4 bytes at offsets
  `+0x48` and `+0x58`. A matching candidate yields its entry pointer; a miss
  returns zero to the caller, which selects a global fallback record rather
  than returning a null pointer.

The match path is a static identity-keyed lookup inference from the observed
key comparisons and table-probe sequence. The generic table's full type,
population path, fallback meaning, and the record byte's role names remain
unresolved. This evidence does not prove the input identity was cryptographically
authenticated before entering the routine.

## Limits

This packet extends only the early common identity lookup. The action-specific
DEX owner check, selector-`0x13` non-owner membership lookup, state mutation,
and nested `UserDisabled` serializer are documented in the linked parent packet
and merged #7109. The public decoder/signature ingress and all component-wide
gates remain open; no `research/progress.json` gate is changed.
