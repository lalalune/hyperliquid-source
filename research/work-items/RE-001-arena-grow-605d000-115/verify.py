#!/usr/bin/env python3
"""Verify RE-001-arena-grow-605d000-115 against the pinned artifact."""
import hashlib, json, os, re, subprocess, sys

P = os.path.dirname(os.path.abspath(__file__))
R = os.path.abspath(os.path.join(P, "..", "..", ".."))
B = os.path.join(R, "work", "hl-node-115.bin")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
OBJDUMP = ["objdump", "-d"]

def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)

def artifact():
    assert os.path.isfile(B), "missing work/hl-node-115.bin"
    assert os.path.getsize(B) == SIZE, "artifact size mismatch"
    digest = hashlib.sha256()
    with open(B, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    assert digest.hexdigest() == SHA, "artifact sha256 mismatch"

def excerpt(name, start, stop, required):
    path = os.path.join(P, "excerpts", name)
    assert os.path.isfile(path), f"missing excerpt {name}"
    saved = open(path, encoding="utf-8").read()
    proc = run(OBJDUMP + [f"--start-address={start}",
                          f"--stop-address={stop}",
                          "work/hl-node-115.bin"], cwd=R)
    assert proc.returncode == 0, proc.stderr[:400]
    def norm(text):
        return [line.split(" <", 1)[0].rstrip()
                for line in text.splitlines() if line.strip()]
    assert norm(saved) == norm(proc.stdout), f"excerpt drift: {name}"
    for needle in required:
        assert needle in saved, f"{name} lacks {needle!r}"

FRAMES = [
    "0075a0ac 000000000000004c 00029e80 FDE cie=00730230 pc=000000000605d000..000000000605d3a1",
    "0036c9ec 0000000000000010 0036c9f0 FDE cie=00000000 pc=00000000060d4f70..00000000060d4f91",
    "0036ca00 0000000000000024 0036ca04 FDE cie=00000000 pc=00000000060d4fa0..00000000060d4fdc",
    "0036ca28 0000000000000010 0036ca2c FDE cie=00000000 pc=00000000060d4fe0..00000000060d4ff8",
    "0036ca3c 0000000000000018 0036ca40 FDE cie=00000000 pc=00000000060d5000..00000000060d5048",
    "0036ca58 0000000000000020 0036ca5c FDE cie=00000000 pc=00000000060d5050..00000000060d5094",
    "0036782c 0000000000000010 00367830 FDE cie=00000000 pc=000000000605e830..000000000605e859",
    "0075a0fc 0000000000000020 00029ed0 FDE cie=00730230 pc=000000000605cfd6..000000000605cffb",
]

def frames():
    path = os.path.join(P, "excerpts", "frames.txt")
    assert os.path.isfile(path), "missing excerpts/frames.txt"
    saved = open(path, encoding="utf-8").read()
    for line in FRAMES:
        assert line in saved, f"frames.txt lacks {line[:40]}..."
    wanted = {line.split()[0] for line in FRAMES}
    proc = subprocess.Popen(["objdump", "--dwarf=frames", B],
                            stdout=subprocess.PIPE, text=True)
    seen = set()
    for line in proc.stdout:
        match = re.match(r"^([0-9a-f]{8}) \S+ \S+ FDE ", line)
        if match and match.group(1) in wanted:
            assert line.strip() in saved, "frames drift vs artifact"
            seen.add(match.group(1))
    assert proc.wait() == 0
    assert seen == wanted, f"missing FDEs in artifact dump: {wanted - seen}"

SAMPLES = [
    (0x605D000, "f30f1efa"),          # grow endbr64
    (0x605D030, "e81b800700"),        # call producer wrapper 0x60d5050
    (0x605D03F, "488b83a8080000"),    # mov finish.last
    (0x605D070, "4801abe0080000"),    # add used counter +0x8e0
    (0x605D086, "e8a5170000"),        # call notify 0x605e830
    (0x605D149, "e8823c3900"),        # call operator new (chunk)
    (0x605D1D7, "e8f43b3900"),        # call operator new (map)
    (0x605D239, "e8423b3900"),        # call operator delete (map)
    (0x605D389, "488d3d004690fa"),    # lea length_error string
    (0x605D395, "f30f1efa"),          # landing pad endbr64
    (0x605D39C, "e935fcffff"),        # jmp shared cleanup block
    (0x60D4F83, "e978bc3100"),        # destroy: jmp munmap PLT
    (0x60D5025, "c1e112"),            # shl $0x12,%ecx (mmap flags)
    (0x60D5031, "e86ac53100"),        # call mmap PLT
    (0x605E846, "f048017708"),        # notify: lock add counter
    (0x605CFD9, "e8927f0700"),        # cleanup: call descriptor destroy
]

def samples():
    with open(B, "rb") as handle:
        blob = handle.read()
    for va, want in SAMPLES:
        got = blob[va - 0x1000:va - 0x1000 + len(want) // 2].hex()
        assert got == want, f"sample {va:#x}: {got} != {want}"
    # the length_error message string lives in the first LOAD segment
    # (vaddr == file offset there), at the lea target 0x961990
    end = blob.index(b"\x00", 0x961990)
    message = blob[0x961990:end].decode()
    assert message == "cannot create std::deque larger than max_size()", \
        f"length_error string drift: {message!r}"

RELOCS = {
    "00000000064ee178", "00000000064ee188", "00000000064ee250",
    "00000000064ee308", "00000000064ee310", "00000000064ee338",
    "00000000064ee340", "00000000064ee3b0", "00000000064ee3b8",
    "00000000064ee720",
}

def relocations():
    path = os.path.join(P, "relocations.txt")
    assert os.path.isfile(path), "missing relocations.txt"
    saved = {line.split()[0] for line in
             open(path, encoding="utf-8") if line.strip()
             and not line.startswith("#")}
    assert saved == RELOCS, "relocations.txt slot set mismatch"
    proc = run(["objdump", "-R", B])
    assert proc.returncode == 0, proc.stderr[:400]
    present = set(re.findall(r"^([0-9a-f]{16}) R_X86_64_JUMP_SLOT",
                             proc.stdout, re.M))
    assert RELOCS <= present, "relocations drift vs artifact"

def records():
    data = json.load(open(os.path.join(P, "records.json"),
                          encoding="utf-8"))
    assert data["work_item"] == "RE-001-arena-grow-605d000-115"
    assert data["artifact"]["sha256"] == SHA
    assert data["artifact"]["bytes"] == SIZE
    wins = {w["name"]: w for w in data["windows"]}
    assert (wins["main"]["start"], wins["main"]["end"],
            wins["main"]["size"]) == ("0x605d000", "0x605d3a1", 929)
    assert data["fields"]["map_offset"] == "0x868"
    assert data["fields"]["used_offset"] == "0x8e0"
    assert data["fields"]["mmap_flags"] == "0x40022"
    assert data["semantics"]["deque_max_size"] == "0x7ffffffffffffff"
    assert data["semantics"]["length_error_message"] == \
        "cannot create std::deque larger than max_size()"
    census = data["census"]
    assert census["main"]["direct_calls"] == ["0x605d73b", "0x605d8af"]
    assert census["producer_wrapper"]["direct_calls"] == ["0x605d030"]
    assert census["descriptor_install"]["direct_calls"] == \
        ["0x605d059", "0x605d15c"]
    assert census["cleanup"]["tail_jumps"] == ["0x605d39c"]
    assert len(data["unknowns"]) >= 1 and len(data["non_claims"]) >= 1
    proc = run([sys.executable, os.path.join(P, "census.py"), B], cwd=R)
    assert proc.returncode == 0, proc.stderr[:400]
    for needle in ("target 0x605d000", "0x605d73b 0x605d8af",
                   "target 0x605cfd6", "0x605d39c"):
        assert needle in proc.stdout, f"census rerun lacks {needle!r}"

def model_and_differential():
    proc = run([sys.executable,
                os.path.join(R, "tests", "test_arena_grow_115.py")], cwd=R)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-1000:]
    assert "0 failed" in proc.stdout, proc.stdout[-400:]
    try:
        import unicorn  # noqa: F401
    except ImportError:
        print("note: unicorn unavailable in this interpreter; "
              "differential step skipped (rerun verify.py with an "
              "interpreter that has unicorn to execute it)")
        return
    proc = run([sys.executable, os.path.join(P, "differential.py")], cwd=R)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-1000:]
    assert "0 failed" in proc.stdout, proc.stdout[-400:]

def manifest():
    path = os.path.join(P, "MANIFEST.sha256")
    assert os.path.isfile(path), "missing MANIFEST.sha256"
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        digest, rel = line.split(None, 1)
        target = os.path.join(P, rel.strip())
        assert os.path.isfile(target), f"manifest target missing: {rel}"
        actual = hashlib.sha256(open(target, "rb").read()).hexdigest()
        assert actual == digest, f"manifest mismatch: {rel}"

def main():
    artifact()
    excerpt("main-605d000.objdump.txt", "0x605d000", "0x605d3a1", [
        "call   60d5050", "call   605e830"])
    excerpt("helpers-60d4f70.objdump.txt", "0x60d4f70", "0x60d4ff8", [
        "jmp    63f0c00", "call   60d4f70"])
    excerpt("create-60d5000.objdump.txt", "0x60d5000", "0x60d5094", [
        "shl    $0x12,%ecx", "call   63f15a0"])
    excerpt("notify-605e830.objdump.txt", "0x605e830", "0x605e859", [
        "lock add %rsi,0x8(%rdi)", "jmp    606a0c0"])
    excerpt("cleanup-605cfd6.objdump.txt", "0x605cfd6", "0x605cffb", [
        "call   60d4f70", "call   63f0a50"])
    frames()
    samples()
    relocations()
    records()
    model_and_differential()
    manifest()
    print("RE-001 arena grow 0x605d000-115 packet verified")

if __name__ == "__main__":
    main()
