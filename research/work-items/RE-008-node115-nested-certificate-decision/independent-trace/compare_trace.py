#!/usr/bin/env python3
"""Compare the independent trace of 0x595fd20 with the expected values of cases.tsv.

Usage: python3 -I compare_trace.py <cases.tsv> <xcheck1/outputs.tsv> --outdir NEW_DIR [--selftest]

--outdir is required and must not exist yet or be an empty directory outside the directories of the two input
files; the report (compare-result.txt, or selftest-result.txt with --selftest) is written there and nothing
else is written anywhere. A sha256 of both inputs is compared before and after the run.

The independent side (xcheck1/outputs.tsv) was computed by a second model (OpenAI GPT-6.1 via Codex CLI)
that was given only the inputs and the binary, without the Rust or the expectations. This script reads
its outputs and the expected columns of cases.tsv (columns out_tag .. ref, produced by gen_corpus.py from
the disassembly). Nothing is executed. Exit status 0 only if no row differs after the normalizations below
and the input columns of cases.tsv are byte-identical to the inputs the independent side was given.

Normalizations (notation only; each is applied the same way to every row):
  N1  numbers: cases.tsv writes words in hex, the independent output in decimal; compared as integers.
  N2  tag: cases.tsv `DIVERGE` (the Rust model's Output::Diverges) is the independent `noreturn`.
  N3  `fwd`: the independent output says "the verifier's own record is the output" instead of copying a
      payload. The expectation must then be the verifier's tag from the INPUT column `validator` and its
      payload word (or no payload for `A`), so N3 also checks the cases.tsv row against its own input.
  N4  `noreturn` rows: the model carries the two pairs in Output::Diverges, the target writes nothing
      before the diagnostic call, so the words column of these rows is not compared (tag, helper/verifier
      call counts and the helper reference still are).

--selftest first runs the comparison on the unmodified inputs and exits 1 if it does not come out clean (a
damaged or mismatching input can therefore never be "rejected 7 of 7"). It then damages one value at a time
in memory, on the expected side and on the independent side (a tag, a call count, a reference word, a payload
word, a `fwd` payload, an id, a one-sided noreturn) and requires, for each damage, a report of exactly the damaged
row and of the field that was damaged (all other fields of that row still equal); exit 1 unless every damage
is reported for its own reason.
"""
import csv
import hashlib
import os
import sys

IN_COLS = ["id", "head", "a", "b", "c", "d", "e", "tail", "ctx_c", "ctx_d", "helper", "validator"]
# sha256 of the independent side's inputs.tsv (same columns, same row order as the projection of cases.tsv)
XCHECK_INPUTS_SHA = "8be05a447bde6ce1840433ed14a198f42dbb434d8c2e95791159936f71bc858a"


def hex_words(s):
    return [] if s == "-" else [int(w, 16) for w in s.split(":")]


def dec_words(s):
    return [] if s == "-" else [int(w) for w in s.split(":")]


def read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compare(cases, indep):
    """Returns (counts, bad). counts: tag, calls, ref, words (compared equal), words_of (compared), fwd, noreturn.
    bad: one dict per differing row: id, group, tag, calls, ref, words (True where equal); for an id sequence
    that differs, a single dict with id None."""
    c = dict(tag=0, calls=0, ref=0, words=0, words_of=0, fwd=0, noreturn=0)
    bad = []
    if [r["id"] for r in cases] != [r["id"] for r in indep]:
        return c, [dict(id=None, group="id sequence differs", tag=False, calls=False, ref=False, words=False)]
    for exp, ind in zip(cases, indep):
        diverge = exp["out_tag"] == "DIVERGE"
        tag_ok = (ind["out_tag"] == "noreturn") if diverge else (ind["out_tag"] == exp["out_tag"])  # N2
        calls_ok = (ind["helper_calls"], ind["validator_calls"]) == (exp["helper_calls"], exp["validator_calls"])
        ref_ok = dec_words(ind["ref"]) == hex_words(exp["ref"])  # N1
        words_ok = True
        if diverge:
            c["noreturn"] += 1  # N4
        else:
            c["words_of"] += 1
            if ind["out_words"] == "fwd":  # N3
                c["fwd"] += 1
                v = exp["validator"]
                want_tag = "2e" if v == "A" else v.split(":")[1]
                want_words = [] if v == "A" else [int(v.split(":")[2], 16)]
                words_ok = exp["out_tag"] == want_tag and hex_words(exp["out_words"]) == want_words
            else:
                words_ok = dec_words(ind["out_words"]) == hex_words(exp["out_words"])  # N1
            c["words"] += words_ok
        c["tag"] += tag_ok
        c["calls"] += calls_ok
        c["ref"] += ref_ok
        if not (tag_ok and calls_ok and ref_ok and words_ok):
            bad.append(dict(id=exp["id"], group=exp["group"], tag=tag_ok, calls=calls_ok, ref=ref_ok, words=words_ok))
    return c, bad


def describe(b):
    if b["id"] is None:
        return b["group"]
    return "%s %s tag=%s calls=%s ref=%s words=%s" % (b["id"], b["group"], b["tag"], b["calls"], b["ref"], b["words"])


def inputs_identical(cases):
    # The independent side got inputs.tsv, a projection of the round-1 cases.tsv: same inputs as now?
    proj = "\t".join(IN_COLS) + "\n" + "".join("\t".join(r[k] for k in IN_COLS) + "\n" for r in cases)
    return hashlib.sha256(proj.encode()).hexdigest() == XCHECK_INPUTS_SHA


def report(cases_path, out_path, cases, indep):
    lines = ["cases.tsv   sha256 %s rows %d" % (sha(cases_path), len(cases)),
             "outputs.tsv sha256 %s rows %d" % (sha(out_path), len(indep))]
    same_inputs = inputs_identical(cases)
    lines.append("input columns of cases.tsv byte-identical to the independent side's inputs.tsv: %s" % same_inputs)
    c, bad = compare(cases, indep)
    n = len(cases)
    lines.append("rows %d" % n)
    lines.append("tag equal              %d/%d" % (c["tag"], n))
    lines.append("helper/verifier calls  %d/%d" % (c["calls"], n))
    lines.append("helper reference       %d/%d" % (c["ref"], n))
    lines.append("payload words          %d/%d compared  (%d noreturn rows not compared: N4; %d of the compared rows are `fwd`, checked against the input validator column: N3)"
                 % (c["words"], c["words_of"], c["noreturn"], c["fwd"]))
    for b in bad[:20]:
        lines.append("DIFF " + describe(b))
    lines.append("differing rows after normalization: %d" % len(bad))
    return lines, (not bad and same_inputs)


FIELDS = ("tag", "calls", "ref", "words")


def selftest(cases, indep):
    """Returns (baseline problem lines, baseline ok, [(name, ok, detail)])."""
    c, bad = compare(cases, indep)
    base_ok = not bad and inputs_identical(cases)
    if not base_ok:
        return [describe(b) for b in bad[:20]] + (["input columns differ from the independent side's inputs"] if not inputs_identical(cases) else []), False, []

    def pick(pred):
        return next(i for i, r in enumerate(cases) if pred(r))

    ind_by_id = dict((x["id"], x) for x in indep)
    plain = pick(lambda r: r["out_tag"] != "DIVERGE" and r["out_words"] != "-" and r["ref"] == "-" and ind_by_id[r["id"]]["out_words"] != "fwd")
    refd = pick(lambda r: r["ref"] != "-")
    fwd = pick(lambda r: ind_by_id[r["id"]]["out_words"] == "fwd" and r["validator"] != "A")
    results = []

    def expect(name, bad, row, field):
        ok = len(bad) == 1 and bad[0]["id"] == row and not bad[0][field] and all(bad[0][f] for f in FIELDS if f != field)
        results.append((name, ok, "; ".join(describe(b) for b in bad[:2]) or "nothing reported"))

    def damage_exp(name, idx, key, value, field):
        rows = [dict(r) for r in cases]
        rows[idx][key] = value
        expect("expected side: " + name, compare(rows, indep)[1], cases[idx]["id"], field)

    def damage_ind(name, idx, key, value, field):
        rows = [dict(r) for r in indep]
        rows[idx][key] = value
        expect("independent side: " + name, compare(cases, rows)[1], cases[idx]["id"], field)

    other_calls = "1" if cases[plain]["helper_calls"] == "0" else "0"
    damage_exp("tag", plain, "out_tag", "ff", "tag")
    damage_exp("helper call count", plain, "helper_calls", other_calls, "calls")
    damage_exp("reference word", refd, "ref", cases[refd]["ref"].replace("0", "1", 1), "ref")
    damage_exp("payload word", plain, "out_words", cases[plain]["out_words"] + ":1", "words")
    damage_exp("fwd payload against the validator column", fwd, "out_words", "1234", "words")
    damage_ind("tag", plain, "out_tag", "ff", "tag")
    damage_ind("helper call count", plain, "helper_calls", other_calls, "calls")
    damage_ind("reference word", refd, "ref", indep[refd]["ref"] + ":1", "ref")
    damage_ind("payload word", plain, "out_words", indep[plain]["out_words"] + ":1", "words")
    rows = [dict(r) for r in cases]
    rows[0]["id"] = "x0000"
    results.append(("expected side: id", [b["id"] for b in compare(rows, indep)[1]] == [None], "id sequence"))
    rows = [dict(r) for r in cases]
    rows[plain]["out_tag"] = "DIVERGE"  # a row turned into noreturn on one side only
    expect("expected side: noreturn on one side only", compare(rows, indep)[1], cases[plain]["id"], "tag")
    return [], True, results


def prepare_outdir(outdir, inputs):
    if not outdir:
        sys.exit("--outdir is required: results are written only to a new directory")
    out = os.path.realpath(outdir)
    for p in inputs:
        d = os.path.dirname(os.path.realpath(p))
        if out == d or out.startswith(d + os.sep):
            sys.exit("--outdir must not be inside the directory of an input file: " + d)
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        sys.exit("--outdir must not exist yet or be an empty directory: " + outdir)
    os.makedirs(out, exist_ok=True)
    return out


def main():
    args = sys.argv[1:]
    if len(args) < 2 or "--outdir" not in args:
        sys.exit("usage: compare_trace.py <cases.tsv> <outputs.tsv> --outdir NEW_DIR [--selftest]")
    outdir = args[args.index("--outdir") + 1]
    cases_path, out_path = args[0], args[1]
    out = prepare_outdir(outdir, [cases_path, out_path])
    before = (sha(cases_path), sha(out_path))
    cases, indep = read(cases_path), read(out_path)
    if "--selftest" in args:
        lines, ok, results = [], True, []
        base_lines, base_ok, results = selftest(cases, indep)
        if not base_ok:
            lines.append("baseline control FAILED: the unmodified inputs do not compare clean, so no damage can be judged")
            lines += base_lines
            ok = False
        else:
            lines.append("baseline control: the unmodified inputs compare clean")
            for name, good, detail in results:
                lines.append("%s\t%s\t%s" % ("rejected" if good else "NOT REPORTED FOR ITS OWN REASON", name, detail))
            lines.append("damages reported for their own reason: %d/%d" % (sum(g for _, g, _ in results), len(results)))
            ok = all(g for _, g, _ in results) and len(results) == 11
        name = "selftest-result.txt"
    else:
        lines, ok = report(cases_path, out_path, cases, indep)
        name = "compare-result.txt"
    if (sha(cases_path), sha(out_path)) != before:
        lines.append("FAIL an input file changed during the run")
        ok = False
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, name), "w", newline="\n") as f:
        f.write(text)
    sys.stdout.write(text)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
