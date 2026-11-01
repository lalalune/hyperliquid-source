# Conditional prepared-path selection

Target: the separate captured Visor, SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes. Coordinates below are ELF virtual addresses. This is a manual
argument over authenticated instructions and records, not instruction execution.

## Domain and premises

Assume the ordinary x86-64 calling convention; valid, stable, nonaliasing input,
global, local and result storage; normal completion of initialization, opaque
helpers and indirect error/cleanup callbacks; and no writes through those helpers
to the retained input/output payloads or unrelated local tuples. The formatter
premises from accepted #1345 remain explicit: callbacks succeed, imported memcpy
has ordinary semantics, allocations supply adequate disjoint storage, and growth
preserves the initialized prefix. Internal allocation and growth are not proved
here and must not be called imported libc realloc.

Let X be the input slice passed in RSI/RDX to `0x3a1780`. After the optional
initialization at `0x3a1a8e..0x3a1abf`, let G be the stable payload at offsets
+8/+16 of the object beginning at `0x7e9e58 + 0x18`. The slot at `0x7e53e8`
uniquely relocates to `0x7e9e58`. This does not identify G with a home directory,
current directory, environment variable, compiled literal or actual runtime value.

All conclusions concern the routine's normal returning paths. Allocation failure,
invalid storage, reentrancy, concurrent mutation, nonreturning callbacks and unwind
are excluded. No filesystem helper contract or actual filesystem state is assumed
to have been established.

## Two byte constructions

At `0x3a1794..0x3a17b3`, the local slice records describe X and the three bytes
`tmp` at `0x795ee`. At `0x3a17d2..0x3a180d`, the argument records are:

1. the object at `global + 0x18`, callback `0x39a750`;
2. the two-word slice `tmp`, callback `0x32cf10`;
3. the two-word input X, callback `0x32cf10`.

The complete stream at `0x65d22` is `c0 01 2f c0 01 2f c0 00`.
The retained formatter driver sends sequential records 0, 1, 2 with literal
slashes in between. Each callback tail-jumps through `0x7e4c50 -> 0x499ae0`:
`0x39a750..0x39a764` reads object +8/+16;
`0x32cf10..0x32cf23` reads slice +0/+8. Neither adds path normalization.
Under the stated formatter/storage premises, the result of the call at
`0x3a1823` is therefore P = G || `/tmp/` || X.

The original P tuple is retained at local `rsp+0x50/+0x58/+0x60` by
`0x3a1829..0x3a1840`. Subsequent component/conversion helpers may change the
separate candidate pointer/length used in checks; they do not establish that P
is normalized or changed. This distinction matters to the returned object.

Only after the first preparation attempt produces a nonzero result does
`0x3a190e..0x3a1933` build the second stream. Its single record points to the
retained P object, again using `0x39a750`. The stream at `0x62043` is exactly
`05 2f 74 6d 70 2f c0 00`: five literal bytes `/tmp/`, then record 0.
Thus Q = `/tmp/` || P. It reuses the entire first construction, including G
and its `/tmp/` segment. For example, G=`root`, X=`shell_rs_out/x` gives
P=`root/tmp/shell_rs_out/x`, Q=`/tmp/root/tmp/shell_rs_out/x`. The strings are
byte concatenations; no slash collapse, canonicalization or path safety follows.

## Which tuple returns

The component/conversion sequence uses unique slots
`0x7e5ef8 -> 0x694cf0`, `0x7e5f30 -> 0x678fa0`, and
`0x7e4d28 -> 0x49b560`. Their detailed contracts remain opaque here. Let A be
the candidate slice selected by the first sequence and B the candidate selected
by the second. They need not equal the full P/Q slice. The second sequence keeps
the full Q pointer/length in R15/R14 while its selected check slice uses RBP/R13.
In particular, `0x3a1a7f..0x3a1a89` changes RBP/R13, not R15/R14.

Call the low-byte predicate result through `0x7e5ef0 -> 0x39fc10` a and b for
the respective attempts. Call the RAX results through
`0x7e5f50 -> 0x679ba0` u and v. These labels denote observed call results,
not proven meanings such as directory existence or successful mkdir.

- `0x3a18cf..0x3a18d1`: a nonzero a branches to `0x3a1a2b`, returning P.
- `0x3a18f5..0x3a18f8`: when a is zero, u=0 also returns P at `0x3a1a2b`.
- With a=0 and u nonzero, the opaque call at `0x3a1906 -> 0x39fd40` is
  retained for later indirect dispatch and Q is constructed.
- `0x3a19d2..0x3a19d4`: nonzero b selects `0x3a1a51`, which stores the full
  Q tuple (R12/R15/R14) into the output and dispatches the earlier opaque value.
- If b=0, `0x3a19f4..0x3a19f7` selects the same Q return when v=0.
- If both a=b=0 and u,v are nonzero, `0x3a1a01..0x3a1a29` dispatches the
  later opaque value, disposes Q when its recorded allocation word is nonzero,
  then dispatches the earlier opaque value. It falls through `0x3a1a2b` and
  copies the original P tuple to the output. It does not select Q on this edge.

The common normal epilogue at `0x3a1a3c..0x3a1a50` returns the output pointer.
The Q return later disposes the retained P allocation and joins that epilogue.
The P return copies local +0x50/+0x58/+0x60, even when temporary checking slices
were replaced. Under the premises, the selected payload T is therefore:

    Q exactly when a == 0 and u != 0 and (b != 0 or v == 0);
    P on all other normal returning paths.

The 16-row boolean table in `check_argument.py` expands this formula, including
the both-attempts-nonzero edge. Values of uncalled operations are don't-care
inputs. This is an algebra check of the manual argument, not a claim that all
16 combinations are reachable in an actual filesystem.

## The shell caller and its later check

The caller `0x3d8d70..0x3d97e9` is retained context from #1266/#1345, not a new
body recovery. It builds X through the `shell_rs_out/` stream at `0x688d6`, then
passes its pointer/length into the output object at `rsp+0xa8` through the call
at `0x3d8def -> 0x7e5f68 -> 0x3a1780`. Thus this packet relates the earlier
formatter's opaque T to X and G under explicit conditions; it does not recover
the source of the timestamp-like earlier payload or the initialized value of G.

At `0x3d8e08..0x3d8e24`, the caller passes the selected output's +8/+16 words
through `0x7e5f48 -> 0x3a0d10`. That companion repeats the candidate-slice
sequence and predicate/preparation calls. Predicate nonzero or preparation RAX=0
returns zero through `0x3a0dc5`. Otherwise it tail-returns the RAX produced by the
opaque direct call `0x3a0dd5 -> 0x39fd40`. Only the caller's observed zero result
continues toward the main command formatter. Nonzero results select its early
cleanup/return. The companion therefore prevents inferring that selecting P on
the two-nonzero edge necessarily leads to a command being prepared or run.

## What is still open

Global initialization and the actual G/X values; component and conversion helper
semantics; predicate and preparation filesystem behavior; error value types and
indirect callback effects; allocation/copy/prefix preservation; failure/unwind;
later process and cleanup behavior; source/Rust type recovery; and whole-component
equivalence remain unproved. Bindings are provided to support later closure,
not to certify these callees from their names or standard-library resemblance.

No captured target, instruction evaluator, emulator, shell command constructed by
the capture, file creation routine from the capture, network operation or chain
action was run. No accepted gate, progress denominator or rebuilt-byte comparison
is changed. The proof is a conditional byte-construction and output-selection
result with explicit call and storage premises.
