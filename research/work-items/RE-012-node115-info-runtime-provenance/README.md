# Resolve the `info` sink's profiling-log provenance

The `info` literal previously followed by the RE-012 info packets belongs to
an allocator profiling-log output path. A relocation-bound `prof.log_start`
control handler initializes the exact pathname buffer consumed by the known
`info` output owner. The same path has a `prof_log` initialization label and
an explicit `<jemalloc>` diagnostic. This resolves a concrete outstanding
role/pathname question for RE-012 CLI reconstruction: these bytes are not
evidence that the node exposes an `info` CLI command.

This is a provenance result and exclusion boundary, not a correction of a
false claim. The prior packets explicitly withheld CLI identity. Their
original evidence remains intact:

- [RE-012-node115-cli-info-literal](../RE-012-node115-cli-info-literal/README.md)
  retains the literal and its then-unresolved role.
- [RE-012-node115-info-string-format-sink](../RE-012-node115-info-string-format-sink/README.md)
  establishes format-key consumption without claiming CLI ownership.
- [RE-012-node115-info-file-sink](../RE-012-node115-info-file-sink/README.md)
  establishes the terminal file sink but leaves pathname initialization open.

The last packet's output callback chain is reused, not rediscovered or
reimplemented. This contribution supplies the upstream registration and both
pathname initialization branches. The downstream consumer is the RE-012
command/role inventory: it can retire this unresolved CLI candidate while
retaining the actual allocator diagnostics behavior for future build work.
No generic allocator reimplementation or new logging feature is proposed.

## Target and method

Target `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are image VAs. The record retains six full FDEs and validates
bytes, ELF relocation/import bindings, selected instructions, strings, control
record data and import thunks. No target execution, emulation, profiling-log
activation, file output or allocator control call was performed.

## Registration binds a role, not just a nearby string

The table entry at `64da690` has name relocation `64da698 -> 4343e3` (`prof`),
child count 11 at `64da6a0`, and child-array relocation
`64da6a8 -> 64dd960`. Its 0x28-stride child at index8 is `64ddaa0`:
name relocation `64ddaa8 -> 43c91b` is `log_start`; no child count/array is
present at +10/+18; its handler relocation is `64ddac0 -> 63777f0`.
This is a structural binding of the `prof`/`log_start` names to the handler,
not an inference from address adjacency. It does not by itself reconstruct
the full public control-name parser or prove an external caller invoked it.

`63777f0` checks byte `6713606`, rejects nonzero old-value arguments
(`rcx | r8`), accepts either no new-value pointer or a new-value size of eight,
and loads the filename pointer from the latter. It passes that pointer as
RSI to `63d4ad8` at `637782b`. A nonzero initializer result maps to error14;
zero maps to success. This establishes an explicit filename-input route.

## The exact pathname buffer and both input branches

`63d4ad8` checks the same global byte `6713606`, enters the existing helper
`63d46b4`, and performs a one-time exit-handler registration. Its failure
message is pinned at `96bd00`: `<jemalloc>: Error in atexit() for logging`.
The operational state at `67157f4` must be zero before a new path is accepted.
The successful branch then sets that state to one at `63d4b90`.

For non-null input RSI, saved as RBX:

1. `63d4b6b` calls the thunk `63f0a80`, whose RIP-relative jump resolves to
   imported `strlen` at `64ee190`.
2. `63d4b70..76` rejects lengths greater than 0x1000. Exactly 4096 is accepted.
3. `63d4b78` computes destination **buffer address** `67147e0`; it does not
   load a pathname pointer from that global.
4. `63d4b7f` sets count to length+1 and `63d4b85` copies those bytes with
   `rep movsb`, including the terminator.

For null input:

1. `63d4b49` loads sequence word `67157e8` and supplies it with that same
   buffer address to `63d7c50`.
2. That helper calls imported `getpid` through thunk `63f0bc0` / slot
   `64ee230`. It chooses a prefix pointer from `67276a8`, or fallback buffer
   address `6712600` if the pointer is null.
3. It calls formatter `63bf47c` with destination, bound0x1001, literal
   `%s.%d.%lu.json` at `44efc4`, prefix, PID, and the supplied sequence.
4. `63d4b5f` increments the global sequence after the helper returns.

This closes the requested filename producer and arguments. Prefix contents,
format truncation/error details, runtime filenames, and initialization of
all global configuration values remain unproven; the packet does not invent
a concrete default filename or a node command-line option.

A separate automatic route also exists: `63c41c0` calls `63d5476` at
`63c43b5`. The latter initializes a context with label `prof_log` (`435410`),
checks its helper result, then conditionally invokes `63d4ad8` with RSI=0
when byte `67157f8` is nonzero. Thus this route selects the generated-path
branch. The source/config origin of that byte is outside this packet.

## Same buffer reaches the established `info` sink

The prior owner `63d4bbe` checks operational state `67157f4 == 1` at
`63d4c04`, changes it to two at `63d4c27`, and on its file-output branch
computes the same address `67147e0` at `63d4c4d`. It passes that address to
the already-established open helper with mode0644. The alternate mode guard
at `67157f0` remains a separate runtime condition; it is not asserted false
for a real invocation.

That owner constructs the existing terminal callback chain and passes
`info` (`4312f2`) to `63d3d27` at `63d4d2d`, exactly the output-key consumer
already established in the prior packet. Therefore the registration, copied
or generated filename, and observed `info` owner are one connected path.
A new raw string hit alone would not establish this provenance.

## Reproduction and limits

```sh
PYTHONPATH=/path/to/capstone-5.0.7-and-pyelftools python3 research/work-items/RE-012-node115-info-runtime-provenance/verify.py --target artifacts/node/115/hl-node
```

The verifier checks six FDEs / 783 instructions, 145 selected witnesses,
four relocations, two import bindings, six labels and five raw data/thunk
ranges. Fourteen negative controls reject wrong target/control records,
wrong initializer, wrong new-value size, omitted profiling gate, different
buffer, incorrect length boundary, missing terminator, wrong default branch,
missing sequence advance, different sink state, omitted automatic-start
gate, wrong formatting bound and wrong numeric argument.

These checks establish retained static evidence and its consistency. They
do not activate the allocator, validate actual log contents, infer the
application's CLI grammar, prove environment/config provenance, reconstruct
all formatting/locking/failure behavior, or close any full component gate.
