# RE-012: common output-option construction on node115

Component: node-runtime. Base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Sole target: Linux x86-64 node115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
105,896,032 bytes. Coordinates are linked ELF virtual addresses before load bias.

## Gap and result

Current main has no common CLI option producer. Prior open PR2034 establishes root
construction and extraction; PR2476 establishes the output record consumer; PR2497
establishes the separate command factory and local command arguments. They leave
this shared constructor at 0x5656bf0 outside their primary scope.

This packet binds all fourteen common declarations to original length-delimited
names, initial flag stores and actual registration calls. It also binds the two
validator tables, the serve-eth-rpc alias entry, the actions internal key for
replica-cmds-style, the three accepted style comparisons and the two actual factory
calls. These are producer/consumer integration facts needed for an independent
startup reconstruction, not another naming inventory or a complete parser.

The standard-library collector is task-specific evidence support. Main's ELF/FDE
tools supply ranges but cannot derive these option stores, relocation writers,
alias entries or callback predicates. It changes no general tool or workflow.

## Observed contract

| Order | Long option | Initial flags |
| --- | --- | --- |
| 1 | write-trades | 0x404 |
| 2 | write-fills | 0x404 |
| 3 | write-raw-book-diffs | 0x404 |
| 4 | write-order-statuses | 0x404 |
| 5 | write-misc-events | 0x404 |
| 6 | write-hip3-oracle-updates | 0x404 |
| 7 | write-user-clearinghouse-states | 0x424 |
| 8 | write-system-and-core-writer-actions | 0x404 |
| 9 | disable-output-file-buffering | 0x404 |
| 10 | batch-by-block | 0x404 |
| 11 | stream-with-block-info | 0x404 |
| 12 | serve-evm-rpc | 0x404 |
| 13 | serve-info | 0x404 |
| 14 | replica-cmds-style | 0x424 |

The fourteen calls use slot 0x64e1cf0, whose sole RELATIVE writer resolves to
0x1638840. Its prior observed global/required bit checks are context, not new
implementation coverage. All initial global/required bits are clear. Full parsing,
default propagation and arbitrary aliases are not proved by these words.

The constructor input is an App-like pointer in RSI, result pointer in RDI, and
the observed copy span is 0x250 bytes. The normal return copies ranges 0..0x90 and
0xa0..0x250, then writes the five-byte 0.1.0 label at +0x90/+0x98. This is object
storage evidence, not a stable Rust ABI or authenticated build version.

At 0x5658d67 and 0x5658dc6, both storage branches point to the same thirteen bytes
serve-eth-rpc. Their entries store length13 and a zero trailing byte; one branch
allocates24 bytes and initializes a one-entry vector, the other appends a
24-byte entry. Official MIT [Clap alias source](https://github.com/clap-rs/clap/blob/d51ae89656fda527ef1bccf53fca0ad78ecb8c29/src/args/arg.rs), alias()
pushes a name with false, whereas visible_alias() pushes true. This is a hidden
alias structural correspondence. Exact vendored version, parser handling and
current-network behavior remain unknown.

The last declaration initially uses replica-cmds-style, then stores the
seven-byte actions internal name while retaining the eighteen-byte long name.
Its table 0x64aa908 has actual RELATIVE methods 0x5620110, 0x5659830, 0x5659830.
The five-byte once adapter tail-jumps to the complete369-byte validator.

The validator compares exact lengths7,14,21. Complete overlapping immediate/SIMD
operands reconstruct actions, recent-actions and actions-and-responses.
Success writes only MIN64 to the first output qword, not a parsed enum value.
Other input writes the26-byte Matching variant not found error through the
shared reserve helper. Both normal paths release the original owned input when
its reloaded capacity is nonzero. The reserve-call landing pad releases temporary
error storage and then the original input before UnwindResume. This contract
assumes valid owned storage, disjoint input/output and ordinary helper behavior.

The clearinghouse-state option instead uses table0x64aacf8 with methods
0x561fb30,0x564e0f0,0x564e0f0: the already studied owned-string callback, not this
style predicate. A numeric interpretation cannot be inferred from its option name.

The sole RELATIVE writer naming the constructor is slot0x64ebcc8. Two qualified
FF15 sites, 0x564e250 and0x564e336, lie in prior PR2497's command factory
0x564e1a0..0x56544a9. They remain credited context. The original static scan found
two unprefixed RIP-relative candidates and no unprefixed E8 direct candidate in
executable sections, then checked each against complete containing-FDE instruction
boundaries. Register/computed calls, prefix forms and code without FDEs are not
proved absent.

## Replay

From the repository root, with the pinned capture materialized:

    python -B tools/node115_cli_common_settings.py --output work/common-settings.json
    python -B -m unittest discover -s tests -p test_node115_cli_common_settings.py -v
    python -O -B -m unittest discover -s tests -p test_node115_cli_common_settings.py -v
    python -B research/work-items/RE-012-node115-cli-common-settings/verify.py
    python -B research/work-items/RE-012-node115-cli-common-settings/verify.py --native-output work/common-native --objdump /absolute/path/to/GNU/objdump

No target execution or emulation is used. Python requires no added package.
Original GNU and Capstone5.0.7/core5.0.1280 observations cover three complete FDEs:
11,696 bytes and1,575 instructions, with no byte masks. Native replay compares
addresses and original bytes, not operand-text equivalence. CLI filename/header
format is not code coverage. Exception headers and call-site tables are decoded;
action/type chains and arbitrary helper unwinding remain open.

## Validation and limits

Initial base make doctor passed. Initial make verify checked all six input
hashes, then failed in native Windows GPG public-key import. The failure remains
failed. Exact final-head make verify/test/catalogue-check/reproduce results accompany
the pull request, separately from these initial observations.

The first collector rejected an operator transcription of the third style name.
The original operands establish actions-and-responses. The rejected run is
preserved separately; no actual predicate, assertion or accepted target changed.
Thirteen controls passed in normal and optimized Python after that correction,
including actual native-row corruption and omission. Fresh native replay matched
all1,575 rows. Seeds1/314159 with UTC/Pacific-Honolulu produced byte-identical
records SHA256e450563d6dedf0bc233f659de0dea73b85015cdf42611d89af3d7e559ef5058b.
These focused results precede the final-head repository checks recorded in the PR.

No Rust implementation, captured execution, stable ABI, parser equivalence,
source-built node, byte-progress registration or component gate is claimed.
Allocator/memcpy/drop implementations, transitive argument grammar, all runtime
callers, defaults and full startup/service side effects remain separate boundaries.
All92 accepted component gates stay false.

Next question: connect these declarations and alias/key relations through the
actual parser to the already established output consumer without inheriting a
Clap version, arbitrary-input contract or captured execution.
