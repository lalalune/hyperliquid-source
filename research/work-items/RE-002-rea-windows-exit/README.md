# RE-002: preserve the REA child exit status on Windows

- Scope: the repository REA launcher. No captured target is opened or run.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Tools observed: Windows, Python 3.10.11, Node 24.22.1, REA 6.8.0, npm 11.6.2.
- Claim: an observed launcher failure, independently reproduced with real CLI
  processes. No Rust implementation or component progress gate is requested.

## Problem and result

`python tools/rea.py <command>` uses `os.execvpe` to launch Node or npm. On the
tested Windows host, the launcher exits zero after starting a child even when
the child fails. A caller can therefore accept a failed REA command or failed
`npm ci` as successful. The same command run directly returns one.

The Windows branch now waits with `os.spawnve(os.P_WAIT, ...)` and exits with
the returned child status. It uses the selected absolute command, arguments
and environment. The Windows C runtime path also retains the existing npm
shim behavior. Unix continues to use `execvpe`.

| Actual process | Direct child | Original launcher | Fixed launcher |
| --- | ---: | ---: | ---: |
| REA unknown-command error | 1 | 0 | 1 |
| `npm ci` without a lockfile, offline | 1 | 0 | 1 |
| REA `--version`, output `6.8.0` | 0 | 0 | 0 |
| Locked offline npm install, no dependencies | — | 0 | 0 |

The install success fixture has a preinstall command that exits 99. Both
launchers retain `--ignore-scripts`, complete successfully and leave the
lockfile unchanged. Install failure fixtures are separate from the real pinned
REA installation. No network registry request, project registration, native
provider, target execution, signing or chain action is involved.

`windows-cases.json` records the allowlisted results and launcher byte hashes.
Full raw process output is retained in the author's local diagnostics; it is
not copied here because npm prints local cache paths.

## Reproduce

Use a supported Windows Node with the project's pinned REA package installed.
Set `REA_NODE` to that absolute Node path. From the repository root:

```powershell
python tools/rea.py --invalid-owned-cli-probe
$LASTEXITCODE
python tools/rea.py --version
$LASTEXITCODE
python -m unittest tests.test_rea_launcher.RuntimeSelectionTests.test_windows_launcher_preserves_command_exit_status
```

The first command prints `COMMAND_NOT_FOUND` and must return 1. The version
command prints `6.8.0` and must return 0. On the baseline the first command
instead returns 0. Repeat against the baseline in a separate checkout with
the same supported runtime and pinned package; do not alter the current
package lock to test an install failure.

The portable regression simulates Windows' observed exec-overlay exit and
checks successful and failed child statuses. The final regression against the
original launcher has one failing subcase, `0 != 23`; the success subcase
passes. The fixed launcher passes both. This simulated status test is distinct
from the real Node/REA/npm process comparisons above.

## Limits and references

Full Windows repository checks need complete LFS/source inputs and are not
claimed by the focused Windows observations. Linux checks and the unchanged
Unix CLI path are reported separately at the PR's final source head. No
process-tree teardown or native Ghidra claim is made.

Python documents that [`P_WAIT`](https://docs.python.org/3/library/os.html#os.P_WAIT)
waits for the spawned process and returns its exit code. The launcher uses it
in one thread. The real Windows controls are the acceptance evidence here.

This differs from PR #526, which finds a supported Node later in PATH, and
PR #220, which reads MCP pipes on Windows. This fix neither changes runtime
selection nor changes the MCP receive loop.
