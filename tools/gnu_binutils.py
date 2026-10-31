"""Detect GNU binutils objdump/readelf for optional test cross-checks.

Same approach as RE-014's gnu_objdump(): read `<tool> --version` and require
"GNU" in the first line. LLVM's objdump/readelf (the macOS default) reject the
GNU-only flags these cross-checks use (-M intel, --no-show-raw-insn, -wf,
--debug-dump=frames, -rW). A non-GNU or missing tool makes the cross-check
SKIP with an explicit reason; a skip is never a pass, and the pure-Python
pinned-output, tamper and mutation tests run regardless.
"""
import shutil
import subprocess
import unittest


def gnu_tool(name):
    """Return (path, version_line) for GNU `name`, or (None, reason)."""
    path = shutil.which(name)
    if not path:
        return None, f"{name} not found on PATH"
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True,
                              env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"{name} --version failed: {exc}"
    text = (proc.stdout or "") + (proc.stderr or "")
    line = text.splitlines()[0] if text.strip() else "(empty --version)"
    if proc.returncode != 0 or "GNU" not in line:
        return None, f"{name} is not GNU binutils (got {line!r})"
    return path, line


def gnu_objdump():
    return gnu_tool("objdump")


def gnu_readelf():
    return gnu_tool("readelf")


def requires_gnu(*names):
    """unittest decorator: skip (never pass) unless every named tool is GNU binutils."""
    for name in names:
        path, why = gnu_tool(name)
        if path is None:
            return unittest.skip(f"SKIPPED (not a PASS): {why}; this cross-check needs GNU binutils")
    return lambda obj: obj
