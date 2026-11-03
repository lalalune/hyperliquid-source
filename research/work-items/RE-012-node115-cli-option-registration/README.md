# RE-012: Node115 option registration writes and ownership boundary

Component: node-runtime. This packet answers one startup question from docs/TASKS.md RE-012: how does the real CLI declaration producer register an argument, and which storage and settings does it change?

Target: Linux x86-64 node115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301, 105,896,032 bytes. All addresses are linked ELF virtual addresses before load bias.

## Result

The exact RELATIVE writer at 0x64e1cf0 names 0x1638840. Fourteen actual calls in the previously studied common producer use that slot. They bind this packet to a real Node115 startup path; their producer bytes remain credited to PR2587 and are not new coverage.

The entry at 0x1638840..0x1638fc3 registers the incoming argument through these observed branches:

- Arg+0x1b0 bit 0x8 calls the reference-registration helper at 0x162cff0, then tail-calls original-argument cleanup at 0x163a670.
- Conditional requirements are copied into App+0x1b8's vector as 0x30-byte records. Source tuples advance by 0x20 and the records add the incoming argument's name pair.
- Required bit 0x1 appends the incoming name to App+0x1a0's 16-byte-pair vector, then adds only requirements with an absent condition tag.
- Group helper 0x162f6e0 walks 16-byte group names and 0x60-byte group records. Its equal-length, byte-comparison-shaped lookup either appends the incoming name or constructs a new group record. The external comparison helper is a boundary.
- Last bit 0x4000 ORs word 0x8040 at App+0x1eb. Exact long names help and version clear App+0x1e8 bits 0x100 and 0x200 respectively.
- An explicit index tag, or the conjunction of no long name and short sentinel 0x110000, selects positional lowering and insertion at App+0x1f8. The automatic index is the current positional count plus one, with an explicit maximum-count panic branch.
- Other arguments use bit 0x20 to choose option-like 0x1e8-byte records or flag-like 0xf0-byte records. Each path sets its unified order from the previous flag and option counts.
- The reference-registration path has corresponding branches. When bit 0x8 is set it calls the helper behind 0x64e1be0, then copies a 0x210-byte result into the global-argument vector at App+0x188/+0x190/+0x198. The clone-like label is a structural inference, not proof of the callee's entire allocation behavior.

The collector checks 21 typed instruction operands, 23 actual calls and three unique RELATIVE writers. The remaining complete helper bodies support the interpretation and bound its unresolved calls. They are not claimed as independently implemented Rust.

## Evidence

Twelve complete unwind-described ranges contain 6,165 bytes and 1,311 instruction rows. Original GNU exports and independently decoded Capstone records agree on every address and byte, without masks. The verifier also checks all retained LSDA call intervals and landing pads against those instruction boundaries.

The main function's LSDA has 15 call-site intervals. Reserve-failure landing pads call the shown flag/option cleanup routines or original-argument cleanup before _Unwind_Resume. Action/type chains and arbitrary exceptions inside transitive callees remain unresolved. A matching exported byte sequence does not establish a stable Rust ABI or full parser equivalence.

Source/base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86. A structural comparison uses MIT Clap source at d51ae89656fda527ef1bccf53fca0ad78ecb8c29, src/app/parser.rs add_arg, add_arg_ref, add_reqs, add_arg_groups and implied_settings:
https://github.com/clap-rs/clap/blob/d51ae89656fda527ef1bccf53fca0ad78ecb8c29/src/app/parser.rs
https://github.com/clap-rs/clap/blob/d51ae89656fda527ef1bccf53fca0ad78ecb8c29/LICENSE-MIT

This correspondence supplies inferred labels. It does not identify the exact vendored revision. No inferred can1357 source was copied. Prior PR2034 root construction, PR2476 parsed-output consumption, PR2497 command construction and PR2587 common declarations remain separately credited context.

## Reproduce

From the repository root, with all pinned inputs materialized:

    python -B tools/node115_cli_option_registration.py --output work/registration.json
    python -B -m unittest discover -s tests -p test_node115_cli_option_registration.py -v
    python -O -B -m unittest discover -s tests -p test_node115_cli_option_registration.py -v
    python -B research/work-items/RE-012-node115-cli-option-registration/verify.py
    python -B research/work-items/RE-012-node115-cli-option-registration/verify.py --native-output work/registration-native --objdump /absolute/path/to/GNU/objdump
    make doctor
    make verify test catalogue-check
    make reproduce

The runtime collector uses only the standard library and existing ELF/FDE readers. Original GNU binutils 2.47 used -d -Mintel --insn-width=16 and the recorded exact range bounds. Independent author-side Capstone binding 5.0.7/core 5.0.1280 came from the existing distribution labelled 5.0.9; it is not a runtime dependency.

## Limits and next question

No captured execution or emulation, network/parser run, chain action, Rust implementation, build-provenance match, full node equivalence or component gate is requested. All unfinished gates remain false. The 1,311-row denominator is exact only for the twelve listed FDEs; no function/caller completeness outside them is implied.

Existing tools export ranges but not these argument-to-registration bindings, flags, vector writes and exception intervals. The task-specific collector and corruption controls are the minimal replay support for this active RE-012 question; existing infrastructure is unchanged.

Next: recover the original borrowed conversions and positional insertion's full ownership/allocator contracts, then independently implement established semantics. Raw matching helper bodies alone do not close those transitive contracts. Final submitted-head mandatory-check results and any Windows failures are disclosed in the PR, separate from focused packet evidence in validation.json.
