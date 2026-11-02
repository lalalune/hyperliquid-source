# RE-012: Node #94 CLI output configuration

- Component: node-runtime; bounded partial static research for RE-012.
- Target: Linux x86-64 Node #94, 91,774,280 bytes, SHA-256
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
- Source base: 966865f1637a29ce75b019e1bf11d5529cc6f519.
- Reference: existing hl-node-startup-inventory-94 packet for the CLI-owner seed.
  No inferred can1357 implementation was copied or used to establish semantics.
- New result: identify the thirteen output bytes and distinguish selected-name
  success, backing-key lookup, and three supplied replica-style values. This
  advances the prior literal inventory into a bounded layout/branch interpretation.
- No Rust implementation, native execution, equivalence or progress-gate claim.
  research/components.json, progress records and generated catalogues are unchanged.

## Observations and inferred contract

The actual FDE is [0x4579310,0x457acef), 6,623 bytes / 1,599 decoded
instructions. Its body SHA-256 is
f3c50a0ed70e10642cf0be14e3c565745efc58b140a809f95b5f74c8a050b312.
The prologue preserves input RSI in R14, output RDI in R12 and loads an optional
selected-name record from input+0x48. For a non-null record, +8 and +0x10 are
used as byte pointer and length. These are observed accesses, not recovered Rust
type names or proof that arbitrary memory states are valid inputs.

For each named field, a matching selected name defines the result byte as one;
a mismatch continues into the backing-key lookup. In the no-selected-name path
the same keys are looked up directly. The common sink stores bytes at R12+0..12
and returns the output pointer. The following interpretation assumes well-formed
caller data, a hash state consistent with the table, valid memory and the observed
bcmp import providing zero exactly when the compared byte ranges are equal:

    out[i] = selected_name_equals(key[i]) OR backing_key_present(key[i])

This is an analyst inference from the retained instructions and joins, not a
formal or execution-tested equivalence statement. The twelve Boolean paths check
key presence; they do not decode an associated Boolean argument value here. Whether
a CLI spelling, default or false-valued argument creates that key is a caller
question, deliberately not answered by this packet.

| Byte | Key | Store VA | Selected equal edge -> block | True definition |
| --- | --- | --- | --- | --- |
| 0 | write-trades | 0x457a2ad | 0x4579368 -> 0x457968f | 0x4579693 |
| 1 | write-fills | 0x457a2b5 | 0x457954c -> 0x45797d6 | 0x45797d6 |
| 2 | write-raw-book-diffs | 0x457a2be | 0x45796dc -> 0x45797ce | 0x45797ce |
| 3 | write-order-statuses | 0x457a2c7 | 0x457981d -> 0x457995a | 0x457995a |
| 4 | write-misc-events | 0x457a2d0 | 0x457994a -> 0x4579b87 | 0x4579b87 |
| 5 | write-hip3-oracle-updates | 0x457a2d5 | 0x4579a88 -> 0x4579b7a | 0x4579b7f |
| 6 | write-system-and-core-writer-actions | 0x457a2de | 0x4579bbc -> 0x457a399 | 0x457a399 |
| 7 | disable-output-file-buffering | 0x457a2e7 | 0x4579d0f -> 0x4579f79 | 0x4579f7d |
| 8 | batch-by-block | 0x457a2f0 | 0x4579e7b -> 0x457a0c8 | 0x457a0c8 |
| 9 | stream-with-block-info | 0x457a2f9 | 0x4579fce -> 0x457a0c0 | 0x457a0c0 |
| 10 | serve-evm-rpc | 0x457a2fe | 0x457a107 -> 0x457a383 | 0x457a383 |
| 11 | serve-info | 0x457a303 | 0x457a21f -> 0x457a376 | 0x457a376 |

The first field's map-only path saves its byte in stack+0x34 and restores EBX at
0x457ac08. Fields 1,2,3,4,6,7,8,9 reach the sink through stack+0x1c,0x18,0x14,
0x10,0x40,0x50,8,0x20 respectively. Field 5 uses a working save at stack+4 and
R13B at the sink; field 10 uses R15B; field 11 uses BPL. R12 is temporarily
reused in the middle of the function, with the output pointer saved/restored.
These details matter: a register name alone does not establish a field mapping.

The map-only true/false joins (VA, hexadecimal) give a short review route through
the long owner body. Each tuple lists true definition, absent-key definition and
the next block. Read the complete raw export to check intervening stores and
register restores; facts.json anchors the associated instructions.

| Key index | True | Absent | Next block |
| --- | --- | --- | --- |
| 0 | 45794e2 | 457a3ad | 457a3b5 |
| 1 | 457a443 | 457a476 | 457a47e |
| 2 | 457a513 | 457a548 | 457a550 |
| 3 | 457a5e5 | 457a61a | 457a622 |
| 4 | 457a6ba | 457a6ef | 457a6f7 |
| 5 | 457a78c | 457a7ba | 457a7bc |
| 6 | 457a86b | 457a8bd | 457a8c5 |
| 7 | 457a966 | 457a99b | 457a9a3 |
| 8 | 457aa33 | 457aa66 | 457aa6e |
| 9 | 457ab05 | 457ab3a | 457ab42 |
| 10 | 457abd2 | 457ac05 | 457ac08 |
| 11 | 457aca3 | 457a233 | 457a235 |

The lookups read control pointer/mask/occupied-count/hash-state at input+0x18,
+0x20,+0x30,+0x38. They inspect 16 control bytes, compare seven-bit fingerprints
from the hash's high bits, enumerate matching candidates, then test key lengths
and bytes. An empty control marker terminates absence; collisions continue
probing. The candidate addressing has a 72-byte reverse bucket stride. This is
not a complete recovered container layout or a library-version attribution.

## Supplied replica command style: output byte 12

The key at 0x457a235 is replica-cmds-style (18 bytes). The lookup call at
0x457a244 targets 0x452f5a0, returning a candidate pointer/length in RAX/RDX.
The owner compares the whole length and overlapping bytes:

| Supplied bytes | Length | Tag | Definition |
| --- | --- | --- | --- |
| actions | 7 | 0 | 0x457a283 |
| actions-and-responses | 21 | 1 | 0x457a343 |
| recent-actions | 14 | 2 | 0x457a2a2 |

The 21-byte comparison uses 16-byte constants at 0x203340 and 0x2069e0 at
input offsets 0 and 5; the eleven overlapping bytes agree. The seven-byte
comparison uses 4+4 bytes at offsets 0/3 and the fourteen-byte comparison uses
8+8 at offsets 0/6. facts.json retains exact fragments, tag instructions,
length checks and branches; verify.py recomposes the strings from target bytes.

A null lookup result branches at 0x457a24c to 0x457ace2 and the call at
0x457ace9. A non-matching supplied value reaches 0x457a351 and call 0x457a370.
Thus this function supplies no normal fallback tag for those paths.
This does NOT show that the real CLI omits a parser-provided default.

## Helper, data and error boundaries

0x473c350..0x473c4b0 is the 352-byte key-hash adapter. It calls 0x4778060
on the string and a one-byte 0xff terminator, then finalizes the state.
The stream helper, table builder and caller invariants are not fully closed.

0x452f5a0..0x452f736 is the 406-byte key/value lookup. After a key match it
checks the value count at bucket-0x10, uses the value pointer at bucket-0x18,
and passes pointer/length through the indirect adapter at 0x452f6f0.
The adapter slot 0x576e3f8 has a RELATIVE addend of 0x157a200.
The 503-byte adapter includes an ASCII fast path to 0x157a3c7 and byte-class
validation paths. Its full Unicode/error behavior is not reconstructed here.

The equal-key import slot 0x576e378 is R_X86_64_GLOB_DAT (type 6), dynsym
index 11, symbol bcmp, addend zero. The equality assumption is the documented
[bcmp](https://man7.org/linux/man-pages/man3/bcmp.3.html)/
[memcmp](https://man7.org/linux/man-pages/man3/memcmp.3.html) contract; no exact
runtime library/version identity is claimed.

Recorded RELATIVE slots: 0x576e048 ->0x157aa10 for an invalid style;
0x576e470 ->0x157a9f0 for missing style; 0x576e468 ->0x157a9b0 for the
lookup conversion's error path. The three extracted formatting/error FDEs
end in indirect calls and have no ordinary return instruction in their extents.
Runtime panic/unwind behavior and eventual termination are outside the closure.
These are error-call observations, not an end-to-end crash demonstration.

All addresses are original ELF virtual addresses, not ASLR-adjusted process
addresses. The verifier maps through file-backed ELF sections. In this target
.text file offsets happen to be VA-0x1000; that shortcut must not be applied to
.data.rel.ro. No byte-normalization masks are used.

## Reproduce and inspect

From the repository root, with Python 3.12 (stdlib plus existing repository
parsers) and a separately authenticated complete Node #94 artifact:

~~~sh
python3 -B research/work-items/RE-012-cli-output-config-94/verify.py --artifact /path/to/hl-node
python3 -O -B research/work-items/RE-012-cli-output-config-94/verify.py --artifact /path/to/hl-node
~~~

The artifact path defaults to artifacts/node/94/hl-node. The expected size and
digest are constants, not caller-overridable identity claims. A Git LFS pointer
is rejected. The parser files' base hashes and packet MANIFEST.sha256 are checked.

Original exports were made on Windows with GNU objdump 2.47, independently
compared instruction-for-instruction against Capstone Python 5.0.7 (distribution
5.0.9). For each [start,end) in facts.json the exact options were:

~~~sh
objdump -d --wide --insn-width=16 -M intel --start-address=START --stop-address=END /path/to/hl-node
~~~

Seven complete FDE extents are included: the owner, two lookup/hash helpers,
the value adapter and three error-call wrappers. Their original stdout is stored
losslessly as raw/*.objdump.txt.gz, with original SHA-256 values in facts.json.
The original export headers contain the operator's D artifact path; no private
dataset, account state or credential is included. All seven stderr outputs were
empty. The input executable was only read, never loaded/executed/emulated.
Use gzip.decompress to inspect the original text without rerunning objdump.
Artifact rights are unchanged; original analysis/verifier code is independently
authored under this repository's MIT terms.

verify.py checks complete native-export byte coverage, actual FDE extents and
digests, pointer/length key bytes, output displacements, selected-name branches,
true definitions, saved slots, style fragments/tags and the imported symbol.
Additional flow/helper anchors bind this analysis to the exact instructions.
Ten deliberately corrupted claim records must be rejected, including wrong field
identity, output offset, branch destination, truth byte, style tag/text/fragment,
FDE end, import name and target identity. These are claim-binding controls, not
behavioral tests or proof that the prose's entire dataflow is formally verified.

Operator record limitation: an output-path mistake replaced an intermediate
two-helper JSON record; it was regenerated from the authenticated target under
a new path and is not presented as retained original bytes. The original native
exports and bytewise cross-checks used here remained intact.

## Results, remaining work and next question

Before this packet, the startup inventory located the CLI owner and literals but
did not describe its output layout. This packet records the thirteen output-byte
mapping, selected-name and map-presence joins, accepted supplied style spellings
and their tag values, plus missing/invalid/error boundaries under stated contracts.
The mechanically reproduced observations and analyst inferences are distinguished
above; whole-node native behavior remains unmeasured.

Repository preparation at the source base: make doctor exited 0; make verify
exited 2 at the Node #115 Git LFS pointer input. Exact final-head repository
checks and focused packet checks are reported with their actual outcomes in the
PR submission. No repository-wide green result or reviewed full-scope gate is
claimed by this packet. No generated catalogue edit is requested.

Next bounded question: follow the actual caller's argument registration/default
construction and verify when each map key exists, including supplied false values
and the replica-style default, without importing a guessed source-level type.
