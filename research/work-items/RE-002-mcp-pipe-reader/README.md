# RE-002: read the owned MCP subprocess pipe on Windows

- Component: analysis/build-provenance tooling, RE-002 prerequisite support.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no reference code used.
- Claim: observed host transport defect; no reconstruction or progress gate requested.
- Scope: JSON-lines input and deadline handling in `tools/rea_mcp_check.py`.
  Provider selection, target loading and native analysis semantics are unchanged.

## Reproduce

Windows, CPython 3.12.14, standard library only. From the repository root:

```sh
python research/work-items/RE-002-mcp-pipe-reader/reproduce.py
python -m unittest discover -s tests -p test_mcp_stdio.py -v
```

The proof reads the original script from the exact baseline commit with `git show`.
It extracts the unchanged selector initialization and `receive` function by AST,
then exercises that path against an actual owned Python child's stdout pipe.
It subsequently sends the identical response through the fixed reader. This is
an OS pipe experiment, not a simulated result of an external REA call.
`before-after.txt` and `transport-tests.txt` retain the observed results.
On Windows the baseline raises `OSError [WinError 10093]`; the fixed reader
returns integer 42. A POSIX run can pass both paths; the defect is Windows-specific.

## Evidence and change

`selectors.DefaultSelector` selects sockets on Windows, not subprocess pipe
handles. The previous reader registers `child.stdout`, then fails in `select`
before accepting the JSON response. A single blocking reader thread now reads
complete binary lines into a queue; the caller waits against one monotonic
deadline. Timeout does not discard a partially received frame. Matching response
IDs, server errors and EOF remain checked. The owned child is terminated/waited
before joining the reader and closing its streams.

Six real-process tests cover multiple frames/notifications, response ID matching,
a 240,024-byte UTF-8 response delivered in 17-byte writes, timeout followed by
completion of the same partial frame, EOF, truncated final frame, and error
responses. Each cleanup verifies the reader thread stopped. No mocks replace
the OS pipe and no captured Hyperliquid program is launched.

This is target-independent transport. Artifact identities are context, not a
claim to have analyzed these targets through REA:

- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Visor: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

No instruction addresses, normalization masks, function-equivalence metrics,
Rust implementation, target execution or native provider result are claimed.

## Required checks and limits

GNU make is unavailable here; the Makefile's Python commands were invoked directly
with UTF-8 mode, Git on PATH, and a workspace temporary directory:

- `python tools/doctor.py`: completed; `analysis_ready=false`, Ghidra and several
  required native tools unavailable. No real REA/Ghidra handshake claimed.
- `python tools/artifacts.py verify`: all eight size/SHA-256 checks passed, then
  failed because GPG is absent. Signature verification did not pass.
- `python tools/verify_imports.py`: failed on the modified reference checkout.
  Windows cannot materialize reserved `node/aux.rs`; LFS materialization also
  remains unstaged. Pins/imported evidence were not changed for this PR.
- `python -m unittest discover -s tests -v`: 363 tests, 127.565 seconds;
  7 failures, 16 errors, 21 skips. All six new transport tests passed. Other
  failures include missing binutils, Windows byte/newline/path expectations and
  temporary-directory cleanup. These counts also appeared in the preceding
  unrelated tooling validation; this is not a full independent baseline proof
  of every failure, and the full suite is not reported as passing.
- `python tools/catalogue.py --check`: failed on a native backslash path
  (`l1\\exchange\\handlers\\14_order.rs`); the existing path-normalization PR is
  outside this change.

Inventory and literal interpretations are unchanged, so `make reproduce` is
not applicable. No generated catalogue or milestone gates were changed. Linux,
macOS, hosted CI and a complete REA 6.8.0 provider handshake were not measured.
Next question: run the standard and reduced native smoke commands with an
installed supported REA/Ghidra environment on Windows and Linux.
