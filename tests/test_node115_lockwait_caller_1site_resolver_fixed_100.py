#!/usr/bin/env python3
"""Unit tests for the #344 lock-wait-caller packet (node #115).

Tamper controls first: each tamper must make the temp-copy verifier fail;
the clean temp copy passes; a byte-exact revert passes again.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-fixed-100"
START = 0x63A3F10
END = 0x63A41D0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools",
                        "node115_lockwait_caller_1site_resolver_fixed_100.py")
SCRATCH = os.path.expanduser("~/workspace/scratch-hl344")
CACHE = os.path.join(SCRATCH, "priors_cache.json")
TMPBASE = os.path.expanduser("~/workspace")

PASS = 0
FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(name + (" :: " + str(detail) if detail else ""))


def make_copy(name):
    tmp = os.path.join(TMPBASE, "tmpcopy-hl344-" + name)
    if os.path.exists(tmp):
        shutil.rmtree(tmp)
    os.makedirs(os.path.join(tmp, "tools"))
    shutil.copy(VERIFIER, os.path.join(
        tmp, "tools", "node115_lockwait_caller_1site_resolver_fixed_100.py"))
    shutil.copytree(PACKET, os.path.join(tmp, "research", "work-items",
                                         SLUG))
    art = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(art)
    os.symlink(os.path.realpath(BIN), os.path.join(art, "hl-node"))
    return tmp


def run_verifier(tmp):
    env = dict(os.environ)
    env["HL_PRIORS_CACHE"] = CACHE
    r = subprocess.run([sys.executable,
                        os.path.join(tmp, "tools",
                                     "node115_lockwait_caller_1site_resolver_fixed_100.py")],
                       capture_output=True, text=True, timeout=900,
                       env=env)
    return r


def main():
    # 1. Clean temp copy passes.
    tmp = make_copy("clean")
    r = run_verifier(tmp)
    check("clean temp copy verifier exit 0", r.returncode == 0,
          r.stdout[-500:] + r.stderr[-500:])

    # 2. Hex flip: one flipped byte in the .hex exhibit must fail.
    tmp = make_copy("hexflip")
    hexp = os.path.join(tmp, "research", "work-items", SLUG,
                        "lockwait_caller_1site_resolver_fixed_100.hex")
    with open(hexp, "rb") as f:
        data = bytearray(f.read())
    data[100] ^= 0xFF
    with open(hexp, "wb") as f:
        f.write(bytes(data))
    r = run_verifier(tmp)
    check("hex flip fails the temp-copy verifier", r.returncode != 0,
          "exit %d" % r.returncode)

    # 3. Strict-count change in records.json (JSON parse/modify) must fail.
    tmp = make_copy("strict")
    recp = os.path.join(tmp, "research", "work-items", SLUG, "records.json")
    with open(recp, "rb") as f:
        orig_bytes = f.read()
    rec = json.loads(orig_bytes.decode())
    rec["census"]["strict"] = 190
    with open(recp, "w") as f:
        json.dump(rec, f, indent=2)
    r = run_verifier(tmp)
    check("strict-count change fails the temp-copy verifier",
          r.returncode != 0, "exit %d" % r.returncode)

    # 4. Call-site change in the objdump exhibit must fail.
    tmp = make_copy("callsite")
    objp = os.path.join(tmp, "research", "work-items", SLUG,
                        "lockwait_caller_1site_resolver_fixed_100.objdump.txt")
    with open(objp) as f:
        text = f.read()
    assert "call   63bf680" in text
    text = text.replace("call   63bf680", "call   63bf681", 1)
    with open(objp, "w") as f:
        f.write(text)
    r = run_verifier(tmp)
    check("call-site change fails the temp-copy verifier",
          r.returncode != 0, "exit %d" % r.returncode)

    # 5. Injected overlap with #333's window must fail disjointness.
    tmp = make_copy("overlap")
    recp = os.path.join(tmp, "research", "work-items", SLUG, "records.json")
    with open(recp, "rb") as f:
        orig_bytes = f.read()
    rec = json.loads(orig_bytes.decode())
    rec["exhibits"].append({"range": "0x6386540..0x638693a",
                            "kind": "injected overlap (tamper test)"})
    with open(recp, "w") as f:
        json.dump(rec, f, indent=2)
    r = run_verifier(tmp)
    check("injected overlap fails the temp-copy verifier",
          r.returncode != 0, "exit %d" % r.returncode)

    # 6. Byte-exact revert of records.json passes again.
    with open(recp, "wb") as f:
        f.write(orig_bytes)
    r = run_verifier(tmp)
    check("byte-exact revert passes again", r.returncode == 0,
          r.stdout[-500:] + r.stderr[-500:])

    # 7. Objdump regeneration matches the exhibit (header lines stripped).
    r = subprocess.run(["objdump", "-d",
                        "--start-address=0x63a3f10",
                        "--stop-address=0x63a41d0", BIN],
                       capture_output=True, text=True, timeout=120)
    strict_re = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    regen = [l for l in r.stdout.splitlines() if strict_re.match(l)]
    with open(os.path.join(
            PACKET, "lockwait_caller_1site_resolver_fixed_100.objdump.txt")) as f:
        exhibit = [l for l in f.read().splitlines() if strict_re.match(l)]
    check("objdump regeneration matches exhibit (headers stripped)",
          regen == exhibit,
          "regen %d lines, exhibit %d lines" % (len(regen), len(exhibit)))

    # 8. MANIFEST sha256 recompute matches.
    manp = os.path.join(PACKET, "MANIFEST.sha256")
    man_ok = True
    with open(manp) as f:
        for line in f.read().strip().splitlines():
            h, name = line.split(None, 1)
            name = name.strip().lstrip("*")
            with open(os.path.join(PACKET, name), "rb") as g:
                if hashlib.sha256(g.read()).hexdigest() != h:
                    man_ok = False
    check("MANIFEST sha256 recompute matches", man_ok)

    # 9. Packet dir contains exactly the 6 expected files, no temp files.
    expect_files = {"README.md", "EVIDENCE.md", "records.json",
                    "MANIFEST.sha256",
                    "lockwait_caller_1site_resolver_fixed_100.hex",
                    "lockwait_caller_1site_resolver_fixed_100.objdump.txt"}
    check("packet dir file set exact (no temp files)",
          set(os.listdir(PACKET)) == expect_files,
          str(sorted(os.listdir(PACKET))))

    # 10. records.json parses; window and site fields are as decoded.
    with open(os.path.join(PACKET, "records.json")) as f:
        rec = json.load(f)
    check("records window range",
          rec.get("window", {}).get("range") == "0x63a3f10..0x63a41d0")
    check("records lock-wait sites 1",
          rec.get("sites", {}).get("lock_wait") == 1)

    # 11. Hex exhibit is 704 raw bytes equal to the binary slice.
    with open(os.path.join(
            PACKET, "lockwait_caller_1site_resolver_fixed_100.hex"), "rb") as f:
        hexb = f.read()
    with open(BIN, "rb") as f:
        f.seek(0x63a3f10 - 0x1000)
        sl = f.read(704)
    check("hex exhibit equals binary slice (independent re-check)",
          len(hexb) == 704 and hexb == sl, str(len(hexb)))

    # 12. Worktree git status shows only the expected untracked paths.
    r = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                       capture_output=True, text=True, timeout=60)
    paths = sorted(l[3:] for l in r.stdout.splitlines())
    check("git status shows only the packet + tools + tests paths",
          paths == ["research/work-items/" + SLUG + "/",
                    "tests/test_node115_lockwait_caller_1site_resolver_fixed_100.py",
                    "tools/node115_lockwait_caller_1site_resolver_fixed_100.py"],
          str(paths))

    # Cleanup temp copies.
    for name in ("clean", "hexflip", "strict", "callsite", "overlap"):
        tmp = os.path.join(TMPBASE, "tmpcopy-hl344-" + name)
        if os.path.exists(tmp):
            shutil.rmtree(tmp)

    print("PASS %d FAIL %d" % (PASS, FAIL))
    if FAILURES:
        print("FAILURES:")
        for f in FAILURES:
            print(" - " + f)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
