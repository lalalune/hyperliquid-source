# RE-001: node115 runtime entry and callback handoff

Component: foundation/startup. Target: Linux x86-64 node #115,
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The existing entrypoint inventory leaves the real main, callback ABI and runtime
initialization unresolved. This packet follows the actual ELF header through
`__libc_start_main`, the 39-byte main wrapper, callback vtable and complete
1,749-byte runtime. It establishes the actual zero SIGPIPE setting, conditional
callback result, descriptor-repair request sequence and errno-address exit guard.
The [contract](CONTRACT.md) distinguishes observed bytes, public-source-supported
interpretations, ordinary-call premises and unresolved callees/unwind behavior.

Five primary FDEs total 1,819 bytes; the 38-byte existing entry stub is supporting
context. Fresh GNU objdump, LLVM objdump and Capstone agree over all six complete
FDEs (1,857 bytes/434 instructions). Actual relocations, vtable/data bytes,
PT_LOAD-backed zero-tail facts and LSDA call-site rows accompany the code.
LLVM's standalone LOCK prefix rows are grouped only with their contiguous valid
LOCK instruction; every byte and raw output is retained, with no byte masking.
Temporary snapshot path headers alone are normalized in native exports.

This advances node115 directly. Historical node94 work was a search lead, not
an accepted implementation. Target115 TLS displacement, saved arguments, pthread
registers, call slots, vtables and exception intervals are freshly validated.
The target's Rust 1.95.0 label is corroborating metadata, not build provenance.
Licensed official source files are retained at commit
`59807616e1fa2540724bfbac14d7976d7e4a3860`, with MIT/Apache notices.

Replay from the repository root:

```sh
python3 -B -m unittest discover -s tests -p test_runtime_entry_115_static.py -v
python3 -O -B -m unittest discover -s tests -p test_runtime_entry_115_static.py -v
GNU_OBJDUMP=objdump LLVM_OBJDUMP=llvm-objdump python3 -O -B \
  research/work-items/RE-001-runtime-entry-115/verify.py \
  --native-output work/runtime115-review
```

On macOS, GNU objdump must precede Apple's objdump on PATH; the retained run
uses `/opt/homebrew/opt/binutils/bin` and `LLVM_OBJDUMP=/usr/bin/objdump`.
Exact tool versions, commands, check results and original failures are retained
in tools.json, commands.json, validation.json and raw-streams.json.gz.
The initial doctor invocation omitted GNU PATH; its recovery is distinct.
Initial tests caught a missing historical-template checkout and two overly
specific diagnostic-text expectations; frozen target facts were unchanged.
The retained source acquisition includes the old exit_guard.rs 404 and the
successful current sys/exit.rs fetch.

No captured binary, emulator, signal handler or network service was run. No
Rust implementation, compiled comparator, byte-coverage increment, source-build
identity, full panic semantics or completed component gate is claimed. Whole
private main, cleanup and alternate-stack helpers remain integration boundaries.
The current 77-file repository sweep is running on this node115 packet worktree;
validation.json records its actual state. The earlier historical sweep was
interrupted after the active tree was retired. Hosted CI is not claimed.
