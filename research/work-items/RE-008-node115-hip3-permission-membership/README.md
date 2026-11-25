# Node 115 HIP-3 selector-scoped identity lookup

This packet follows the unresolved non-owner authorization call in the merged
`disableDex` trace, PR #6660. At the `disableDex` call site the action's
selector is `0x13`; the shared helper first selects an entry using that byte,
then walks the selected value's nested records and compares the supplied
20-byte identity against 20-byte candidates. A positive result is required for
the handler to continue.

The packet proves the static data flow and selector-specific membership shape.
It does not identify the application-level meaning of selector `0x13`, prove
which public role it denotes, establish where authorization data is populated,
or claim behavior for other HIP-3 operations. It makes no native execution,
replay, or authorization-safety claim.

## Reproduction

```sh
python3 research/work-items/RE-008-node115-hip3-permission-membership/verify.py
```

The verifier authenticates the pinned node #115 ELF, checks the selector,
caller/helper instruction bytes and FDE extents, confirms that the helper's
indirect comparison slot resolves to imported `memcmp`, and rejects a
one-byte mutation of the comparison call. It reads the ELF only.

## Findings

- The merged writer packet identifies raw `Hip3DeployAction` tag 14 as
  `disableDex`, and its dispatch table selects permission selector `0x13`.
- The handler passes a record field at `row+0x50`, a 20-byte identity at its
  stack offset `+0x2d0`, and the selector in `DL` to `0x469e170`.
- A false return is routed to the existing error path; a true return continues
  to the action-specific path.
- `0x469e170` handles two collection layouts. Both lookup paths choose an
  indexed value using the selector; one walks a tagged compact representation,
  the other performs a binary search over 32-byte records.
- The selected value supplies a nested record walk. The helper reads a 16-bit
  count at record offset `+0xe6`, compares 20-byte candidates at 20-byte
  strides, and follows further record pointers through an indexed area at
  `+0xe8` when the current path does not return. The exact source-level
  collection type and ownership of these fields remain unknown.
- Each candidate comparison uses imported `memcmp` through GOT slot
  `0x64dfb50`. Equality returns true. A false result at the call site routes
  to the existing error path. This is a selector-scoped identity membership
  check, with the data population and domain role unresolved.

The two lookup callees (`0x35bf6c0` and `0x4552d70`) implement different
container representations. This packet does not assign source-language
container or domain-role names to those layouts, and does not establish that
the candidate records are sorted or explain their early-exit invariant.

## Boundaries and overlap

This is a direct follow-up to the explicit unresolved authorization-helper
scope in [PR #6660](https://github.com/lalalune/hyperliquid-source/pull/6660),
not a duplicate of its owner-match or disabled-state write. It closes the
helper's static comparison path only. It does not establish role management,
crypto authentication, permission mutation, other writers, trading admission,
durable persistence, or restart behavior.

Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
