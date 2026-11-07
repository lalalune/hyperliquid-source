"""Checker for RE-001-objectregistry-second-mutex-115.

Run from the repository root:
    python3 research/work-items/RE-001-objectregistry-second-mutex-115/verify.py

Checks, in order:
  1. artifact digest against provenance/artifacts.json
  2. MANIFEST.sha256 entries (hash + exactly two spaces + name)
  3. excerpt regeneration against a fresh objdump run (relative binary path)
  4. fixed samples + 3 seeded random gate spots byte-for-byte against fresh
     objdump AND the raw binary (vaddr -> file offset via PT_LOAD segments)
  5. FDE ranges in frames.txt against a fresh objdump --dwarf=frames run
  6. census reproduction (1,632 mutex PLT sites with the pinned split,
     8 disp-0x70 / 28 disp-0x98 sites, 74 destroy-helper callers with no
     0x70/0x98 displacement and none in a registry-marked FDE, 32 marked
     FDEs, 216 disp hits, 3 getter calls, the 3 library lockers)
  7. model constants (layout, FDE ranges, census constants, lockers)
  8. relocation records against a fresh readelf -rW run
  9. absent strings in the raw binary ("Object already exists: ",
     "Registered Plugins:", and any case of "managed")
 10. the dispose excerpt contains no destroy-helper call and no
     pthread_mutex_destroy call
 11. the model test suite passes (29 checks)
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
BIN_ABS = os.path.join(ROOT, BIN)

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("ctor-61f91b0.objdump.txt", 0x61F91B0, 0x61F9277),
    ("clone-61f9400.objdump.txt", 0x61F9400, 0x61F963E),
    ("dispose-61f8760.objdump.txt", 0x61F8760, 0x61F89DB),
    ("add-library-61f8dc0.objdump.txt", 0x61F8DC0, 0x61F913D),
    ("ttl-register-62069f0.objdump.txt", 0x62069F0, 0x6206D29),
    ("big-method-5ff88c0.objdump.txt", 0x5FF88C0, 0x5FF9C50),
    ("destroy-helper-60d5170.objdump.txt", 0x60D5170, 0x60D5200),
    ("lock70-5f44c80.objdump.txt", 0x5F44C80, 0x5F44D56),
    ("lock70-5f44db0.objdump.txt", 0x5F44DB0, 0x5F44E53),
    ("lock70-606a450.objdump.txt", 0x606A450, 0x606A604),
    ("lock70-606a650.objdump.txt", 0x606A650, 0x606A88E),
    ("lock70-606a900.objdump.txt", 0x606A900, 0x606AA82),
]

# (vaddr, instruction bytes) pinned by direct reads of the excerpts.
FIXED_SAMPLES = [
    (0x61F91B0, bytes.fromhex("f30f1efa")),          # ctor endbr64
    (0x61F9234, bytes.fromhex("488d0505033100")),    # ctor lea map 0x6509540
    (0x61F9491, bytes.fromhex("0f114870")),          # clone movups parent
    (0x61F8EF0, bytes.fromhex("4c8db598000000")),    # AddLibrary lea +0x98
    (0x5FF8A28, bytes.fromhex("e833813f00")),        # big-method lock call
    (0x6206B73, bytes.fromhex("e8e89f1e00")),        # TTL lock call
    (0x5F44C92, bytes.fromhex("e8c9be4a00")),        # lock70 call
    (0x60D5189, bytes.fromhex("e812c63100")),        # destroy PLT call
]

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL:", msg)


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", data, off)
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1:
            segs.append((p_offset, p_vaddr, p_filesz))
    return segs


def v2o(segs, vaddr):
    for p_offset, p_vaddr, p_filesz in segs:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


def objdump(args):
    return subprocess.run(["objdump"] + args + [BIN], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout


def parse_excerpt(path):
    """(vaddr, bytes) pairs from one objdump excerpt file.

    Long instructions wrap: the continuation line carries an address but
    no mnemonic, so its bytes are appended to the previous instruction.
    """
    out = []
    line_re = re.compile(r"^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)(.*)$")
    for line in open(path):
        m = line_re.match(line)
        if not m:
            continue
        b = bytes.fromhex(m.group(2).replace(" ", ""))
        if m.group(3).strip() == "":
            if out:
                prev_addr, prev_bytes = out[-1]
                out[-1] = (prev_addr, prev_bytes + b)
            continue
        out.append((int(m.group(1), 16), b))
    return out


def main():
    data = open(BIN_ABS, "rb").read()
    segs = segments(data)

    # 1. artifact digest
    art = json.load(open(os.path.join(ROOT, "provenance", "artifacts.json")))
    want = None
    for a in art.get("files", []):
        if a.get("path") == "artifacts/node/115/hl-node":
            want = a.get("sha256")
    if want != DIGEST:
        fail("provenance digest mismatch: %r" % want)
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")

    # 2. manifest
    manifest = open(os.path.join(HERE, "MANIFEST.sha256")).read().splitlines()
    for line in manifest:
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
        if not m:
            fail("manifest line malformed: %r" % line)
            continue
        path = os.path.join(HERE, m.group(2))
        if not os.path.exists(path):
            fail("manifest file missing: " + m.group(2))
            continue
        actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if actual != m.group(1):
            fail("manifest hash mismatch: " + m.group(2))

    # 3. excerpt regeneration
    for name, start, stop in WINDOWS:
        fresh = objdump(["-d", "--start-address=" + hex(start),
                         "--stop-address=" + hex(stop)])
        saved = open(os.path.join(HERE, name)).read()
        if fresh != saved:
            fail("excerpt mismatch on regeneration: " + name)

    # 4. fixed samples + seeded random gate spots vs objdump AND raw binary
    excerpts = []
    for name, _s, _e in WINDOWS:
        excerpts += parse_excerpt(os.path.join(HERE, name))
    by_addr = dict(excerpts)
    samples = list(FIXED_SAMPLES)
    rng = random.Random(115)
    picks = rng.sample(excerpts, 3)
    samples += [(a, b) for a, b in picks]
    for vaddr, expect in samples:
        off = v2o(segs, vaddr)
        if off is None:
            fail("no file offset for %#x" % vaddr)
            continue
        if data[off:off + len(expect)] != expect:
            fail("raw binary mismatch at %#x" % vaddr)
        if by_addr.get(vaddr) != expect:
            fail("excerpt mismatch at %#x" % vaddr)
    print("gate spots: " + ", ".join(hex(a) for a, _b in picks))

    # 5. FDE ranges
    frames = objdump(["--dwarf=frames"])
    fdes = {}
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames):
        fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    for name, start, stop in WINDOWS:
        if fdes.get(start) != stop:
            fail("FDE mismatch for %s: %#x..%#x" % (name, start, stop))
    if fdes.get(0x61F92B0) != 0x61F93C5:
        fail("getter FDE mismatch")

    # 6. census reproduction
    sys.path.insert(0, HERE)
    import census as C
    lock_sites, destroy_sites, marked_fdes, disp_hits, getter_calls = C.scan()
    by_call = Counter(s[2] for s in lock_sites)
    if len(lock_sites) != 1632:
        fail("lock sites != 1632: %d" % len(lock_sites))
    if by_call != {"pthread_mutex_lock": 224, "pthread_mutex_unlock": 916,
                   "pthread_mutex_trylock": 487, "pthread_mutex_init": 4,
                   "pthread_mutex_destroy": 1}:
        fail("lock split mismatch: %s" % dict(by_call))
    disp70 = [s for s in lock_sites
              if s[4] == 0x70 and s[2] in ("pthread_mutex_lock",
                                           "pthread_mutex_unlock")]
    disp98 = [s for s in lock_sites
              if s[4] == 0x98 and s[2] in ("pthread_mutex_lock",
                                           "pthread_mutex_unlock")]
    if len(disp70) != 8:
        fail("disp-0x70 sites != 8: %d" % len(disp70))
    if len(disp98) != 28:
        fail("disp-0x98 sites != 28: %d" % len(disp98))
    if len(destroy_sites) != 74:
        fail("destroy-helper callers != 74: %d" % len(destroy_sites))
    if any(s[3] in (0x70, 0x98) for s in destroy_sites):
        fail("a destroy-helper caller passes a 0x70/0x98 displacement")
    if any(s[1] in marked_fdes for s in destroy_sites):
        fail("a destroy-helper caller is in a registry-marked FDE")
    if len(marked_fdes) != 32:
        fail("marked FDEs != 32: %d" % len(marked_fdes))
    if len(disp_hits) != 216:
        fail("disp hits != 216: %d" % len(disp_hits))
    if sorted(a for a, _f in getter_calls) != [0x5FF88FC, 0x61F9420, 0x6206A3D]:
        fail("getter calls mismatch: %s" % [hex(a) for a, _ in getter_calls])
    # The three library lockers: lock site, +0x98 displacement, FDE.
    for site, fde in ((0x61F8F09, 0x61F8DC0), (0x5FF8A28, 0x5FF88C0),
                      (0x6206B73, 0x62069F0)):
        hit = [s for s in lock_sites
               if s[0] == site and s[2] == "pthread_mutex_lock"
               and s[4] == 0x98 and s[1] == fde]
        if not hit:
            fail("library locker missing: %#x" % site)
    # The 5 foreign +0x70 lock FDEs.
    foreign = sorted({s[1] for s in disp70})
    if foreign != [0x5F44C80, 0x5F44DB0, 0x606A450, 0x606A650, 0x606A900]:
        fail("foreign lock70 FDEs mismatch: %s" % [hex(f) for f in foreign])
    # records.json cross-check.
    rec = json.load(open(os.path.join(HERE, "records.json")))
    if rec["lock_census"]["plt_call_sites_total"] != len(lock_sites):
        fail("records.json lock total mismatch")
    if rec["lock_census"]["disp_0x70_sites"] != len(disp70):
        fail("records.json disp70 mismatch")
    if rec["lock_census"]["disp_0x98_sites"] != len(disp98):
        fail("records.json disp98 mismatch")
    if rec["destroy_census"]["destroy_helper_callers"] != len(destroy_sites):
        fail("records.json destroy callers mismatch")
    if rec["disp_census"]["registry_marked_fdes"] != len(marked_fdes):
        fail("records.json marked FDEs mismatch")
    if rec["disp_census"]["disp_0x70_0x97_hits_in_marked_fdes"] != len(disp_hits):
        fail("records.json disp hits mismatch")

    # 7. model constants
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import objectregistry_second_mutex_115 as model
    if model.REGISTRY_SIZE != 0xC0:
        fail("model registry size wrong")
    if model.OBJECTS_MUTEX != 0x70 or model.LIBRARY_MUTEX != 0x98:
        fail("model mutex offsets wrong")
    if model.MUTEX_SIZE != 0x28:
        fail("model mutex size wrong")
    if model.ZERO_CHUNKS != (16, 16, 8):
        fail("model zero chunks wrong")
    if model.CTOR_FDE != (0x61F91B0, 0x61F9277):
        fail("model ctor FDE wrong")
    if model.CLONE_FDE != (0x61F9400, 0x61F963E):
        fail("model clone FDE wrong")
    if model.DISPOSE_FDE != (0x61F8760, 0x61F89DB):
        fail("model dispose FDE wrong")
    if model.LOCK_SITES_TOTAL != 1632:
        fail("model lock total wrong")
    if model.DESTROY_HELPER_CALLERS != 74:
        fail("model destroy callers wrong")
    if model.MARKED_FDES != 32:
        fail("model marked FDEs wrong")
    if model.DISP_HITS != 216:
        fail("model disp hits wrong")
    if len(model.LIBRARY_LOCKERS) != 3:
        fail("model library lockers wrong")
    if model.GETTER_CALLERS != (0x5FF88FC, 0x61F9420, 0x6206A3D):
        fail("model getter callers wrong")

    # 8. relocation records
    relocs = C.relocations()
    saved = open(os.path.join(HERE, "relocations.txt")).read().splitlines()[1:]
    want_rows = []
    for line in saved:
        if not line.strip():
            continue
        parts = line.split("\t")
        want_rows.append((int(parts[0], 16), parts[1], parts[2], parts[3]))
    if relocs != want_rows:
        fail("relocations.txt mismatch against fresh readelf -rW")
    if len(relocs) != 31:
        fail("relocation rows != 31: %d" % len(relocs))
    raw_relocs = subprocess.run(["readelf", "-rW", BIN_ABS],
                                capture_output=True, text=True,
                                check=True).stdout
    for want_line in (
            "00000000064e2300  0000003d00000006 R_X86_64_GLOB_DAT      "
            "0000000000000000 pthread_mutex_lock@GLIBC_2.2.5 + 0",
            "00000000064ee820  000001aa00000007 R_X86_64_JUMP_SLOT     "
            "0000000000000000 pthread_mutex_destroy@GLIBC_2.2.5 + 0",
            "00000000064d8f10  0000000000000008 R_X86_64_RELATIVE     "
            "                    61f8760"):
        if want_line not in raw_relocs:
            fail("relocation record missing: " + want_line[:60])

    # 9. absent strings in the raw binary, and the one "managed" string
    for needle in (b"Object already exists: ", b"Registered Plugins:"):
        if needle in data:
            fail("string present in binary: %r" % needle)
    managed_hits = [m.start() for m in re.finditer(b"managed", data.lower())]
    if managed_hits != [0x95F620]:
        fail("managed-string hits mismatch: %s" % [hex(h) for h in managed_hits])
    elif data[0x95F620:0x95F620 + len(
            b"Managed iterator is not supported anymore.")] != \
            b"Managed iterator is not supported anymore.":
        fail("sole managed string text mismatch")

    # 10. the dispose excerpt never calls the destroy helper
    dispose = open(os.path.join(HERE, "dispose-61f8760.objdump.txt")).read()
    if "60d5170" in dispose:
        fail("dispose excerpt calls the destroy helper")
    if "pthread_mutex_destroy" in dispose:
        fail("dispose excerpt calls pthread_mutex_destroy")

    # 11. model tests
    out = subprocess.run([sys.executable,
                          os.path.join(ROOT, "tests",
                                       "test_objectregistry_second_mutex_115.py")],
                         capture_output=True, text=True)
    # unittest writes its progress and the OK verdict to stderr.
    if out.returncode != 0 or ("OK" not in out.stdout and "OK" not in out.stderr):
        fail("model tests failed: " + out.stdout + out.stderr)
    if "Ran 29 tests" not in out.stderr:
        fail("model test count != 29: " + out.stderr)

    if FAILS:
        print("%d CHECK(S) FAILED" % len(FAILS))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
