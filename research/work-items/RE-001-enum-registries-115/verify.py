#!/usr/bin/env python3
"""Verify the RE-001-enum-registries-115 packet (RE-001).

Checks, in order:
1. The bound artifact digest matches provenance/artifacts.json.
2. MANIFEST.sha256 matches every packet file.
3. Every objdump excerpt regenerates byte-for-byte from the real
   binary (fresh objdump run).
4. The census reproduces registries.tsv byte-for-byte.
5. Three seeded random gate spots from the excerpts match a fresh
   objdump run and the raw bytes at that address.
6. The parse helpers' threshold/hash/memcmp claims and the type-14
   4-byte store; the serialize cases' registry lea, reverse scan and
   shared assign jump.
7. The .init_array RELATIVE relocation (slot 96 -> thunk 0x60c8710)
   and the thunk's jump to the initializer 0x60c78a0.
8. The model tests in tests/test_enum_registries_115.py pass.

Usage: python3 verify.py  (run from the repo root)
Prints ALL CHECKS PASSED on success.
"""

import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
TESTS = ROOT / "tests" / "test_enum_registries_115.py"

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    if not ok:
        FAILURES.append(name)


def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def normalized_excerpt(text):
    """Accept GNU's two spellings of the observed implicit segment operands."""
    return (text.replace("\trep stos %eax,%es:(%rdi)", "\trep stos %eax,(%rdi)")
                .replace("\trep movsb %ds:(%rsi),%es:(%rdi)", "\trep movsb (%rsi),(%rdi)"))


def main():
    records = json.loads((HERE / "records.json").read_text())
    digest = records["artifact"]["sha256"]
    prov = json.loads((ROOT / "provenance" / "artifacts.json")
                      .read_text())
    match = any(digest in json.dumps(v) for v in prov.values()) \
        or digest in json.dumps(prov)
    check("artifact digest in provenance/artifacts.json", match, digest[:16])

    # 2. Manifest.
    manifest_ok = True
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        want, name = line.split(None, 1)
        got = hashlib.sha256((HERE / name.strip()).read_bytes()).hexdigest()
        if got != want:
            manifest_ok = False
            print("  manifest mismatch:", name)
    check("MANIFEST.sha256 matches packet files", manifest_ok)

    # 3. Excerpt regeneration.
    sys.path.insert(0, str(HERE))
    import export_excerpts
    with tempfile.TemporaryDirectory() as tmp:
        regen_ok = True
        for name, start, stop in export_excerpts.EXCERPTS:
            out = run(["objdump", "-d",
                       f"--start-address=0x{start:x}",
                       f"--stop-address=0x{stop:x}", "work/hl-node-115.bin"])
            if normalized_excerpt(out.stdout) != normalized_excerpt((HERE / name).read_text()):
                regen_ok = False
                print("  excerpt mismatch:", name)
        check("excerpts regenerate byte-for-byte", regen_ok)

        # 5. Three seeded random gate spots.
        lines = []
        for name, _, _ in export_excerpts.EXCERPTS:
            for line in (HERE / name).read_text().splitlines():
                m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
                if m:
                    lines.append((int(m.group(1), 16), m.group(2).strip(),
                                  m.group(3).strip()))
        random.seed(0)
        spots = random.sample(lines, 3)
        gate_ok = True
        data = BIN.read_bytes()
        for addr, hexbytes, asm in spots:
            out = run(["objdump", "-d",
                       f"--start-address=0x{addr:x}",
                       f"--stop-address=0x{addr + 16:x}",
                       "work/hl-node-115.bin"])
            fresh = [l for l in out.stdout.splitlines()
                     if l.strip().startswith(f"{addr:x}:")]
            if not fresh or asm not in fresh[0]:
                gate_ok = False
                print("  gate spot mismatch at", hex(addr))
                continue
            raw = data[addr - 0x1000:addr - 0x1000
                       + len(bytes.fromhex(hexbytes))]
            if raw.hex() != hexbytes.replace(" ", ""):
                gate_ok = False
                print("  gate spot raw-bytes mismatch at", hex(addr))
        check("3 seeded gate spots byte-for-byte vs fresh objdump "
              "and raw binary", gate_ok,
              ", ".join(hex(a) for a, _, _ in spots))

    # 4. Census reproduction.
    with tempfile.TemporaryDirectory() as tmp:
        import census
        saved = census.HERE
        census.HERE = Path(tmp)
        census.DUMP = HERE / "static-initializer-60c78a0.objdump.txt"
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            census.main()
        census.HERE = saved
        regen = (Path(tmp) / "registries.tsv").read_text()
        check("census reproduces registries.tsv",
              regen == (HERE / "registries.tsv").read_text())

    # 6. Parse-helper and serialize-case claims.
    parse_ok = True
    for option_type, helper in records["parse"]["helpers"].items():
        text = (HERE / f"parse-{helper['helper'][2:]}.objdump.txt") \
            .read_text()
        for needle in ["cmpq   $0x14,0x18(%rdi)", "_Hash_bytes", "memcmp"]:
            if needle not in text:
                parse_ok = False
                print("  parse helper missing", needle, helper)
        four = "mov    0x28(%rbx),%eax" in text
        if helper["field_bytes"] == 4 and not four:
            parse_ok = False
            print("  type-14 helper lacks the 4-byte store")
        if helper["field_bytes"] == 1 and four:
            parse_ok = False
            print("  non-14 helper has a 4-byte store")
    check("parse helpers: threshold/hash/memcmp, type-14 width",
          parse_ok)

    ser_ok = True
    fn = (HERE / "fn-60ba600.objdump.txt").read_text()
    for option_type, case in records["serialize"]["cases"].items():
        i = fn.find(case["case"][2:] + ":")
        seg = fn[i:i + 1500]
        if case["registry"][2:] not in seg or "0x28(%rsi),%al" not in seg \
                and "0x28(%rsi),%eax" not in seg:
            ser_ok = False
            print("  serialize case mismatch", case)
    check("serialize cases: registry lea, reverse scan, shared "
          "assign", ser_ok and "60bab28" in fn)

    # 7. init_array slot 96.
    rel = run(["readelf", "-r", "work/hl-node-115.bin"]).stdout
    m = re.search(r"0*63f39c8\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                  rel)
    check(".init_array slot 96 RELATIVE -> thunk 0x60c8710",
          m is not None and int(m.group(1), 16) == 0x60C8710)
    thunk = (HERE / "init-thunk-60c8710.objdump.txt").read_text()
    check("thunk jumps to the initializer 0x60c78a0",
          "jmp    60c78a0" in thunk)

    # 8. Model tests.
    res = run([sys.executable, "-m", "pytest", "-q", str(TESTS)])
    check("model tests pass", res.returncode == 0,
          (res.stdout.strip().splitlines() or [""])[-1])

    print()
    if FAILURES:
        print("FAILURES:", ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
