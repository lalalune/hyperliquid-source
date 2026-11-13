# Vault constructor temporary across transfer error and unwind

Advances HL115-064 / RE-001 by binding an actual outer constructor's owned
184-byte temporary to its transfer invocation and error/unwind cleanup. This
is a local ownership boundary, not a claim that the complete transaction rolls
back, commits atomically or persists partially.

Target node115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF disassembly and exception metadata only; no native execution or
emulation. Four windows contain 1,941 bytes / 395 instructions, 227 anchored
facts and 229 rejected controls, including changed exception landing targets.

## Prior work

[#2220](https://github.com/lalalune/hyperliquid-source/pull/2220) covers entry
guards. `RE-001-node115-vault-value-transfer` establishes the selected
`0x44ae810` debit/context-subtract/credit/context-add sequence and delegates
share adjustment to `0x44ad9e0`; it explicitly leaves outer ownership and
rollback unresolved. [#5577](https://github.com/lalalune/hyperliquid-source/pull/5577)
recovers a selected share-row continuation of that helper, not its complete
prepass or transaction rollback. [#6587](https://github.com/lalalune/hyperliquid-source/pull/6587)
and [#6635](https://github.com/lalalune/hyperliquid-source/pull/6635) are prior
guard/context work. This packet does not repeat their arithmetic or claim
that dropping a local object undoes borrowed-context changes.

## Actual temporary and borrowed-context handoff

On the admitted constructor branch, `0x44ae320` builds a 0xb8-byte value at
`rsp+0xc8`. Its owned descriptor fields at +0x20/+0x38 are moved from the
constructor input, its +0x50/+0x58/+0x60 region begins as an empty flat
container, and its tag is the Boolean derived from an input byte. The retained
instructions also show metadata, two 20-byte identities and flags initialized
in that same temporary.

At `0x44ae58a..0x44ae5ad`, the constructor passes:

- output = `rsp+0x180`;
- vault = `rsp+0xc8`;
- identity in RDX, amount in RCX, metadata in R8, mode 1 in R9;
- the separately supplied context-triple pointer as the seventh stack argument.

The actual target is `0x44ae810` through relocation `0x64e7bb0`. At its entry,
the vault is retained in RBP; the separate stack argument is loaded at
`0x44ae8c0`, and its first word supplies the transfer context. These are
separate ownership channels, under the normal valid/nonalias input premise.
The constructor does not make a snapshot of the shared transfer context in
its local 0xb8-byte vault value.

The previously recovered transfer path calls `0x447db40`, subtracts context
+0x4a8, calls `0x4472ea0`, adds context +0x4a8 back, and then invokes
`0x44ad9e0` at **0x44aee4c**. The selected instruction window binds that actual
last invocation and its vault/context arguments; the predecessor remains the
source for the complete earlier admission and value-update contract.

## Normal result ownership

The constructor checks the transfer's result against `0x8000000000000019`.
On that error arm it copies the error payload to output, writes outer tag 1,
and calls `0x44e0b60` with **the same `rsp+0xc8` temporary** at `0x44ae654`.
On the other selected arm, it first disposes of the transfer result via
`0x44e1250`, copies **0xb8 bytes** from the temporary to output +8, and writes
outer tag 0. Thus its successful result moves the value; the error branch
destroys it. No claim is made that a normal returned error can occur after
all the value writes: the instruction evidence does not establish such a
failure trigger.

## Actual unwind route

The exception tables independently identify the owning frames and call sites:

| Owning FDE | LSDA | Call-site interval | Inspected call | Landing |
| --- | --- | --- | --- | --- |
| `0x44ae810` | `0x33bacc` | `0x44ae810` + `0x9e7` | share helper at `0x44aee4c` | none |
| `0x44ae320` | `0x33baa8` | `0x44ae58a` + `0x29` | transfer at `0x44ae5ad` | `0x44ae7e7`, action 0 |

If an unwind escapes the share-helper call, this selected core call-site has
no local landing. The constructor's call-site instead identifies cleanup
`0x44ae7e7`. That landing saves the exception pointer in RBX, passes
`rsp+0xc8` to `0x44e0b60` at `0x44ae7f2`, restores the exception argument and
calls the unwind-resume routine at `0x44ae7fa`. It performs no explicit write
through the borrowed transfer-context pointer before resuming. If cleanup
itself unwinds, a different landing invokes the existing abort boundary;
normal cleanup return is a premise of the stated resume sequence.

This is an actual metadata-bound route, not an inference that nearby code is
a catch block. The verifier parses both recorded type-table encodings,
requires the FDE-to-LSDA association, locates the unique call-site interval and
checks the target/action. Controls changing the constructor landing or
inventing a local core landing are rejected independently of the file hash.

## What the temporary's destructor does

`0x44e0b60` releases nonempty buffers described by temporary +0x20/+0x28 and
+0x38/+0x40. For the **flat +0x50 representation**, a nonzero capacity frees
its +0x58 backing pointer at 72 bytes per capacity element; zero capacity
skips that release. With tag <2 it then returns. Under that selected valid
layout and normal deallocator behavior, these are owned-allocation releases,
not restoration of context +0x4a8 or inverse calls to the debit/credit helpers.

The tree representation at +0x50 delegates to `0x3913600`, and tags >=2 have
another traversal via `0x39094e0`; their complete semantics remain opaque in
this contribution. The post-helper state is not assumed still flat merely
because the constructor initialized it flat. The general unwind proof stops
at the actual destructor call, while the release-only characterization is
explicitly conditional on its inspected layout branches.

## Reproduction and limits

```sh
python3 research/work-items/RE-001-node115-vault-constructor-unwind-owner/verify.py --target /path/to/hl-node
```

The packet checks the original target, exact instruction boundaries, FDEs,
relocations, exception call-site ownership and corruption controls. It does
not execute a failing transfer or manufacture a stubbed failure oracle.

Downstream transaction work can now distinguish cleanup of this temporary
vault from rollback of the shared transfer context. Remaining work includes
an actual outer transaction commit/discard owner, the share-helper prepass,
all destructor subobjects and unwind cases, failure reachability, persistence
and concurrency. The absence of a local inverse write is not evidence that
no higher layer rolls back or discards the encompassing state.
