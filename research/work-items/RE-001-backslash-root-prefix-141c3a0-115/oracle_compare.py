r"""Exhaustive oracle comparison + corruption controls for 0x141c3a0.

Confronts two mechanically-independent descriptions of node #115
routine 0x141c3a0:

  * the hand model, tools/backslash_root_prefix_141c3a0_115.py
    (a reading of the disassembly), and
  * the byte-level interpreter, interp_141c3a0.py (an execution of
    the 51 raw bytes pulled from the ELF via its program headers).

It (1) compares them over every buffer of length 0..4 drawn from a
byte alphabet that covers each relevant class, plus deterministic
length 5..6 samples, recording which buffer indices the interpreter
actually reads to prove the "never index >= 4 / byte[3] only when
len>3" claims; and (2) applies four one-byte corruption patches to a
copy of the routine and shows each patched interpreter diverges from
the model on concrete witnesses, while the unpatched interpreter
matches the model on 100% of inputs.

Output is deterministic (no Date/random): ``render_report`` builds a
stable text block, written to ``oracle_results.txt`` and re-checked
by verify.py.
"""

import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(PACKET))

from backslash_root_prefix_141c3a0_115 import backslash_root_prefix  # noqa: E402
import interp_141c3a0 as interp  # noqa: E402

# Alphabet: one representative per byte class the routine distinguishes.
#   0x00 low control         0x2f '/'            0x3a ':'  (the colon)
#   0x41 'A' ascii letter    0x5c '\\' (backsl.) 0x7f high ascii / boundary
#   0x80 first continuation  0xbf last continu.  0xc0 first non-cont high
#   0xff top byte
ALPHABET = [0x00, 0x2F, 0x3A, 0x41, 0x5C, 0x7F, 0x80, 0xBF, 0xC0, 0xFF]


def _enumerate_len(length):
    n = len(ALPHABET)
    total = n ** length
    idx = [0] * length
    for _ in range(total):
        yield bytes(ALPHABET[i] for i in idx)
        for pos in range(length - 1, -1, -1):
            idx[pos] += 1
            if idx[pos] < n:
                break
            idx[pos] = 0


def _sample_len(length, step):
    """Deterministic stride sample of the length-``length`` space."""
    n = len(ALPHABET)
    total = n ** length
    i = 0
    while i < total:
        digits = []
        x = i
        for _ in range(length):
            digits.append(ALPHABET[x % n])
            x //= n
        digits.reverse()
        yield bytes(digits)
        i += step


def iter_buffers():
    """All length 0..4 buffers over ALPHABET, then length 5..6 samples."""
    for length in range(0, 5):
        for buf in _enumerate_len(length):
            yield buf
    for length, step in ((5, 97), (6, 997)):
        for buf in _sample_len(length, step):
            yield buf


def _model_al(buf):
    return 1 if backslash_root_prefix(buf) else 0


def compare(code):
    """Compare interpreter vs model over iter_buffers(); return a summary."""
    total = 0
    matches = 0
    mismatches = []
    max_read_index = -1
    oob = []
    idx3_when_short = []   # buffers that read index 3 with len <= 3 (claim: none)
    read_ge4 = []          # buffers that read any index >= 4 (claim: none)
    len_buckets = {}

    for buf in iter_buffers():
        total += 1
        len_buckets[len(buf)] = len_buckets.get(len(buf), 0) + 1
        try:
            al, reads = interp.run(code, buf)
        except interp.OutOfBounds as exc:
            oob.append((buf.hex(), exc.index))
            continue
        if reads:
            top = max(reads)
            if top > max_read_index:
                max_read_index = top
            if top >= 4:
                read_ge4.append(buf.hex())
            if 3 in reads and len(buf) <= 3:
                idx3_when_short.append(buf.hex())
        if al == _model_al(buf):
            matches += 1
        else:
            if len(mismatches) < 20:
                mismatches.append((buf.hex(), al, _model_al(buf)))

    return {
        "total": total,
        "matches": matches,
        "mismatches": mismatches,
        "max_read_index": max_read_index,
        "oob": oob,
        "idx3_when_short": idx3_when_short,
        "read_ge4": read_ge4,
        "len_buckets": len_buckets,
    }


# --- corruption controls ----------------------------------------------------

# (label, byte-offset within the 51-byte routine, replacement byte)
CONTROLS = [
    ("cmpb $0x5c -> $0x2f  (leading-backslash test at 0x141c3a7)", 9, 0x2F),
    ("cmpw $0x5c3a -> $0x2f3a  (drive-root test at 0x141c3c9)", 46, 0x2F),
    ("jl (7c) -> jge (7d)  (byte[1] boundary guard at 0x141c3b6)", 22, 0x7D),
    ("ja (77) -> jae (73)  (length>3 branch at 0x141c3bc)", 28, 0x73),
]


def _patched(code, offset, value):
    b = bytearray(code)
    b[offset] = value
    return bytes(b)


def control_divergences(code):
    """For each patch, count/collect buffers where it diverges from the model.

    The patched interpreter is run with ``allow_patched_jcc`` so jge/jae
    decode (they only appear in the patched copies). A divergence is a
    differing ``al``, or the patched routine performing an out-of-bounds
    read the model never does. Range: the length 0..4 enumeration.
    """
    buffers = [buf for length in range(0, 5) for buf in _enumerate_len(length)]
    results = []
    for label, offset, value in CONTROLS:
        patched = _patched(code, offset, value)
        if patched == code:
            raise AssertionError("patch %r did not change a byte" % label)
        witnesses = []
        count = 0
        for buf in buffers:
            model_al = _model_al(buf)
            try:
                pal, _ = interp.run(patched, buf, allow_patched_jcc=True)
                diverges = pal != model_al
                detail = ("al=%d vs model=%d" % (pal, model_al)) if diverges else None
            except interp.OutOfBounds as exc:
                diverges = True
                detail = "patched reads OOB index %d (model al=%d, reads only in-bounds)" % (
                    exc.index, model_al)
            if diverges:
                count += 1
                if len(witnesses) < 3:
                    witnesses.append((buf.hex() or "(empty)", detail))
        results.append({
            "label": label,
            "offset": offset,
            "value": value,
            "divergences": count,
            "witnesses": witnesses,
        })
    return results, len(buffers)


# --- report -----------------------------------------------------------------

def render_report(code, summary, controls, control_pool):
    lines = []
    lines.append("# Oracle comparison -- node #115 routine 0x141c3a0")
    lines.append("")
    lines.append("routine bytes (%d): %s" % (len(code), code.hex()))
    lines.append("alphabet: %s" % " ".join("0x%02x" % b for b in ALPHABET))
    lines.append("")
    lines.append("## Exhaustive interpreter-vs-model comparison")
    buckets = ", ".join("len%d=%d" % (k, summary["len_buckets"][k])
                        for k in sorted(summary["len_buckets"]))
    lines.append("buffers: %d  (%s)" % (summary["total"], buckets))
    lines.append("matches: %d" % summary["matches"])
    lines.append("mismatches: %d" % len(summary["mismatches"]))
    for h, al, mal in summary["mismatches"]:
        lines.append("  MISMATCH %s interp=%d model=%d" % (h, al, mal))
    lines.append("out-of-bounds reads: %d" % len(summary["oob"]))
    for h, i in summary["oob"]:
        lines.append("  OOB %s index=%d" % (h, i))
    lines.append("")
    lines.append("## Read-index proof")
    lines.append("max buffer index read over all buffers: %d" % summary["max_read_index"])
    lines.append("buffers reading any index >= 4: %d" % len(summary["read_ge4"]))
    lines.append("buffers reading index 3 while len <= 3: %d" % len(summary["idx3_when_short"]))
    lines.append("")
    lines.append("## Corruption controls (length 0..4 pool = %d buffers)" % control_pool)
    lines.append("unpatched interpreter mismatches on the same pool: 0 (see above: %d/%d match)"
                 % (summary["matches"], summary["total"]))
    for c in controls:
        lines.append("")
        lines.append("* %s" % c["label"])
        lines.append("  patch: routine byte[%d] := 0x%02x" % (c["offset"], c["value"]))
        lines.append("  divergences from model: %d" % c["divergences"])
        for h, detail in c["witnesses"]:
            lines.append("    witness %s -> %s" % (h, detail))
    lines.append("")
    return "\n".join(lines)


def build_report(path=None):
    code = interp.read_routine_bytes(path)
    summary = compare(code)
    controls, pool = control_divergences(code)
    text = render_report(code, summary, controls, pool)
    return text, summary, controls


def assert_healthy(summary, controls):
    """Raise unless the unpatched oracle matches 100% and every patch diverges."""
    if summary["mismatches"]:
        raise AssertionError("oracle mismatch: %r" % summary["mismatches"][:3])
    if summary["oob"]:
        raise AssertionError("oracle out-of-bounds read: %r" % summary["oob"][:3])
    if summary["matches"] != summary["total"]:
        raise AssertionError("oracle match count %d != total %d"
                             % (summary["matches"], summary["total"]))
    if summary["max_read_index"] > 3:
        raise AssertionError("oracle read index %d > 3" % summary["max_read_index"])
    if summary["read_ge4"]:
        raise AssertionError("oracle read index >= 4 on %r" % summary["read_ge4"][:3])
    if summary["idx3_when_short"]:
        raise AssertionError("oracle read index 3 with len<=3 on %r"
                             % summary["idx3_when_short"][:3])
    for c in controls:
        if c["divergences"] <= 0:
            raise AssertionError("control %r did not diverge" % c["label"])


if __name__ == "__main__":
    text, summary, controls = build_report()
    assert_healthy(summary, controls)
    out = PACKET / "oracle_results.txt"
    if len(sys.argv) > 1 and sys.argv[1] == "--write":
        out.write_text(text)
        print("wrote %s" % out)
    else:
        sys.stdout.write(text)
