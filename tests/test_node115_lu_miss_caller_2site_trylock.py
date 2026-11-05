#!/usr/bin/env python3
"""Unit tests for the #321 lu-miss 2-site trylock packet verifier.

Runs the TEMP COPY's verifier (never the original path), tamper-first:
hex flip, strict-count change, call-site change, and an injected partial
overlap of #320's window each make the temp verifier fail; the clean temp
copy passes. Also independent recounts and objdump regeneration.
"""
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_REL = os.path.join("research", "work-items",
                          "RE-001-node115-lu-miss-caller-2site-trylock")
VERIFIER_REL = os.path.join("tools",
                            "node115_lu_miss_caller_2site_trylock.py")
NAME = "lu_miss_caller_2site_trylock"
START, END = 0x63C9650, 0x63C9C80

PASS = 0
FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL: " + label + " :: " + detail)


def run_verifier(cwd):
    # Share one fingerprint-validated priors cache across the temp runs
    # (see the verifier); the first run collects fresh, the rest reuse it.
    env = dict(os.environ)
    env["HL_PRIORS_CACHE"] = os.path.join(
        os.path.dirname(ROOT), "scratch-hl321", "priors_cache.json")
    r = subprocess.run([sys.executable, VERIFIER_REL],
                       cwd=cwd, capture_output=True, text=True, timeout=900,
                       env=env)
    return r.returncode, r.stdout + r.stderr


def make_temp(tag):
    # Temp dir lives directly under ~/workspace so the verifier's
    # ROOT/../hl-wt-calls*/ prior glob still resolves to the real worktrees.
    # Lean copy: the verifier only needs its own file, the packet dir, and
    # the node binary (symlinked); a full 8641-file copytree x5 is the
    # slow part of the old harness and changes nothing the verifier reads.
    base = os.path.join(os.path.dirname(ROOT), "hl-wt-test321-" + tag)
    if os.path.exists(base):
        shutil.rmtree(base)
    os.makedirs(os.path.join(base, "tools"))
    os.makedirs(os.path.join(base, "research", "work-items"))
    shutil.copy(os.path.join(ROOT, VERIFIER_REL),
                os.path.join(base, VERIFIER_REL))
    shutil.copytree(os.path.join(ROOT, PACKET_REL),
                    os.path.join(base, PACKET_REL))
    os.makedirs(os.path.join(base, "artifacts", "node", "115"))
    os.symlink(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"),
               os.path.join(base, "artifacts", "node", "115", "hl-node"))
    assert os.path.exists(os.path.join(base, "artifacts", "node", "115", "hl-node"))
    return base


def packet_paths(wt):
    pdir = os.path.join(wt, PACKET_REL)
    return {
        "dir": pdir,
        "records": os.path.join(pdir, "records.json"),
        "hex": os.path.join(pdir, NAME + ".hex"),
        "objdump": os.path.join(pdir, NAME + ".objdump.txt"),
        "manifest": os.path.join(pdir, "MANIFEST.sha256"),
    }


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main():
    # 1. clean temp copy passes
    wt = make_temp("clean")
    code, out = run_verifier(wt)
    check("clean temp copy verifier exit 0", code == 0, out[-500:])
    m = re.search(r"PASS count: (\d+), FAIL count: (\d+)", out)
    check("clean temp copy reports 0 fails",
          m is not None and m.group(2) == "0", out[-300:])
    verifier_checks = int(m.group(1)) if m else -1
    pm = re.search(r"priors scanned: (\d+)", out)
    check("clean run scanned real priors",
          pm is not None and int(pm.group(1)) >= 50000,
          out[-300:])
    shutil.rmtree(wt)

    # 2. hex flip tamper fails
    wt = make_temp("hexflip")
    p = packet_paths(wt)
    hb = bytearray(read_bytes(p["hex"]))
    hb[10] ^= 0xFF
    write_bytes(p["hex"], bytes(hb))
    code, _ = run_verifier(wt)
    check("hex flip tamper fails", code != 0)
    shutil.rmtree(wt)

    # 3. strict-count change tamper fails (edit records.json, parsed JSON)
    wt = make_temp("strict")
    p = packet_paths(wt)
    orig_records = read_bytes(p["records"])
    rec = json.loads(orig_records.decode())
    rec["census"]["strict"] = 364
    write_bytes(p["records"], json.dumps(rec).encode())
    code, _ = run_verifier(wt)
    check("strict-count change tamper fails", code != 0)
    # revert must restore BYTES, not a json.dump rewrite (MANIFEST hash)
    write_bytes(p["records"], orig_records)
    code, _ = run_verifier(wt)
    check("byte-exact revert passes again", code == 0)
    shutil.rmtree(wt)

    # 4. call-site change tamper fails
    wt = make_temp("callsite")
    p = packet_paths(wt)
    rec = json.loads(read_bytes(p["records"]).decode())
    rec["lu_miss_sites"][0]["site"] = "0x63c9c2a"
    write_bytes(p["records"], json.dumps(rec).encode())
    code, _ = run_verifier(wt)
    check("call-site change tamper fails", code != 0)
    shutil.rmtree(wt)

    # 5. injected partial overlap of #320's window fails
    wt = make_temp("overlap")
    p = packet_paths(wt)
    rec = json.loads(read_bytes(p["records"]).decode())
    rec["exhibits"].append({
        "name": "injected-overlap",
        "range": "0x635e2e0..0x635e2f0",
        "bytes": 16, "strict": 0, "calls_total": 0, "ret": 0,
        "bin_table_init_sites": [], "lu_miss_sites": [], "bsr": 0,
        "lock_sub": 0, "lock_add": 0, "ret_sites": [], "tail_jump_exits": [],
    })
    write_bytes(p["records"], json.dumps(rec).encode())
    code, _ = run_verifier(wt)
    check("injected partial overlap tamper fails", code != 0)
    shutil.rmtree(wt)

    # 6. independent recounts from the real exhibit
    pdir = os.path.join(ROOT, PACKET_REL)
    obj = read_bytes(os.path.join(pdir, NAME + ".objdump.txt")).decode()
    lines = [l for l in obj.splitlines()
             if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
    check("independent strict recount 363", len(lines) == 363, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("independent call recount 12", len(calls) == 12, str(len(calls)))
    hexb = read_bytes(os.path.join(pdir, NAME + ".hex"))
    node = read_bytes(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"))
    check("independent hex bytes equal binary slice",
          hexb == node[START - 0x1000:END - 0x1000])

    # 7. objdump regeneration (stripped through the 'file format' line)
    r = subprocess.run(["objdump", "-d",
                        "--start-address=0x63c9650",
                        "--stop-address=0x63c9c80",
                        os.path.join(ROOT, "artifacts", "node", "115", "hl-node")],
                       capture_output=True, text=True, timeout=120)

    def strip_to_disasm(text):
        lines = text.splitlines()
        for i, l in enumerate(lines):
            if "file format" in l:
                return lines[i + 1:]
        return lines

    regen = strip_to_disasm(r.stdout)
    exhibit = strip_to_disasm(obj)
    check("objdump regeneration matches exhibit",
          regen == exhibit,
          "regen %d lines vs exhibit %d lines" % (len(regen), len(exhibit)))

    print("TESTS PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    print("verifier checks in clean run: %d" % verifier_checks)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
