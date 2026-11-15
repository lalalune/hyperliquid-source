#!/usr/bin/env python3
"""Compile and test wrong implementations of the crate, one source edit each.

Usage: python3 -I mutate.py <repository root> --outdir NEW_DIR [--only ID[,ID...]] [--add-mutant ID::file::old::new]

--outdir is required and must not exist yet or be an empty directory outside the crate directories and the
packet; mutations.tsv and report.txt are written there and nowhere else. The repository tree is only read:
every mutant is built in a scratch copy (the crate, its path dependencies and the case files, same relative
layout), and a hash of every copied input is compared before and after the run.

A baseline run of the unmodified crate comes first; it must build and every test must pass, and its list of
tests (binary and name) is the inventory every mutant run has to report on. Per mutant, building and
testing are separate steps:
  built      `cargo test --no-run` succeeded (a build failure is an error, never a kill)
  results    every test of the inventory has a result line (a missing result is an error: the run did not
             really happen, e.g. a broken toolchain or an I/O error)
  killed     at least one test of the inventory reports FAILED
  survived   all tests ran and passed
The exit status is 0 only if the baseline passes and every selected mutant is built, has complete results and
is killed. A build error, an incomplete result set, a cargo failure without a failing test, a surviving mutant
or an input that changed during the run each give exit status 1. The failing tests and the corpora with
mismatches are written sorted, so the file does not depend on the order cargo happens to print them in. The
corpora named are those whose captured output (shown by cargo for a failing test) has a nonzero mismatch count.

--only runs a subset (development, and the negative controls of negative_controls.py). --add-mutant adds one
more mutant (testing aid: a harmless edit must be reported as surviving).
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

CRATES = ["node115-nested-certificate-decision", "node115-stake-predicate", "node115-certificate-long-sort",
          "node115-sponge-permutation", "node115-varint-buffer-writer"]
PACKET = "research/work-items/RE-008-node115-nested-certificate-decision"
SRC = "src/node115-nested-certificate-decision/src/"
VARINT = "../../node115-varint-buffer-writer/src/lib.rs"  # relative to SRC
TIMEOUT = 1500

MUTANTS = [
    # decision.rs: the 0x595fd20 core
    ("D01", "pair-equal arm: f30 < b becomes f30 <= b", "decision.rs", "if cert.f30 < b {", "if cert.f30 <= b {"),
    ("D02", "newer-pair test: a > c becomes a >= c", "decision.rs", "if a > c {", "if a >= c {"),
    ("D03", "pair equality ignores the second word", "decision.rs", "if a == c && b == d {", "if a == c {"),
    ("D04", "ordering: f38 < f30 becomes f38 <= f30", "decision.rs", "if cert.f38 < cert.f30 &&", "if cert.f38 <= cert.f30 &&"),
    ("D05", "ordering: b <= f40 becomes b < f40", "decision.rs", "b <= cert.f40 &&", "b < cert.f40 &&"),
    ("D06", "ordering: f40 <= f38 becomes f40 < f38", "decision.rs", "cert.f40 <= cert.f38 {", "cert.f40 < cert.f38 {"),
    ("D07", "equality helper not called (assumed true)", "decision.rs",
     "equals_reference(cert, &empty_reference(cert))", "{ let _ = equals_reference; true }"),
    ("D08", "equality helper result ignored", "decision.rs",
     "equals_reference(cert, &empty_reference(cert))", "{ let _ = equals_reference(cert, &empty_reference(cert)); true }"),
    ("D09", "verifier rejection returned instead of dropped (a > c)", "decision.rs",
     "drop(result);", "return Output::Forwarded(result);"),
    ("D10", "0x2d payload words f38 and f40 swapped", "decision.rs",
     "Output::OutOfOrder { f30: cert.f30, f38: cert.f38, f40: cert.f40 }",
     "Output::OutOfOrder { f30: cert.f30, f38: cert.f40, f40: cert.f38 }"),
    ("D11", "signed comparison of f30 against b", "decision.rs", "if cert.f30 < b {", "if (cert.f30 as i64) < (b as i64) {"),
    ("D12", "last hash byte ignored", "decision.rs", "cert.hash != [0; 32]", "cert.hash[..31] != [0; 31]"),
    ("D13", "first hash byte ignored", "decision.rs", "cert.hash != [0; 32]", "cert.hash[1..] != [0; 31]"),
    ("D14", "f38 == b check removed from the empty-shape test", "decision.rs",
     "cert.f38 != b || cert.f40 != b ||", "cert.f40 != b ||"),
    ("D15", "verifier acceptance ignored when a > c (no divergence)", "decision.rs",
     "if result.tag() == TAG_CONTINUE {", "if false {"),
    ("D16", "divergence arguments swapped", "decision.rs",
     "Output::Diverges { current: ctx.pair, observed: cert.pair }",
     "Output::Diverges { current: cert.pair, observed: ctx.pair }"),
    ("D17", "comparison order reversed: a > c becomes a < c", "decision.rs", "if a > c {", "if a < c {"),
    ("D18", "helper reference record: f38 word is 0 instead of b", "decision.rs",
     "f30: b, f38: b, f40: b,", "f30: b, f38: 0, f40: b,"),
    ("D19", "verifier not called on the ordered path (assumed continue)", "decision.rs",
     "return Output::Forwarded(verify(cert, ctx));", "return { let _ = verify; Output::Continue };"),
    ("D20", "mismatch payload halves swapped", "decision.rs",
     "Output::Mismatch { cert: cert.pair, ctx: ctx.pair }", "Output::Mismatch { cert: ctx.pair, ctx: cert.pair }"),
    ("D21", "decide_nested: equality helper replaced by true", "decision.rs",
     "sig_maps_equal(&c.sigs, &reference.sigs)", "true"),
    # equality.rs, sigmap.rs: 0x4e08870 / 0x4e550e0 and the collection
    ("E01", "entry compare ignores the signature", "equality.rs", "if ka == kb && sa == sb => {}", "if ka == kb => {}"),
    ("E02", "entry compare ignores the key", "equality.rs", "if ka == kb && sa == sb => {}", "if sa == sb => {}"),
    ("E03", "ring order ignores the head", "sigmap.rs", "rows[(head + i) % rows.len()]", "rows[i % rows.len()]"),
    ("E04", "tree visited in reverse key order", "sigmap.rs", "SigMap::Tree(m) => m.iter().collect(),",
     "SigMap::Tree(m) => m.iter().rev().collect(),"),
    ("E05", "normalized rows: signature taken from tail[5..70]", "sigmap.rs", "&r.tail[4..69]", "&r.tail[5..70]"),
    ("E06", "normalized rows: storage classes swapped", "sigmap.rs",
     "StorageClass::Tree => SigMap::tree(n.rows.iter().map(row)),\n            StorageClass::Flat => {",
     "StorageClass::Flat => SigMap::tree(n.rows.iter().map(row)),\n            StorageClass::Tree => {"),
    # round 3: wrong value on the entry path (the V5 finding), tree and ring
    ("T01", "tree entry gets the signature of the next key (one value slot off)", "sigmap.rs",
     "SigMap::Tree(m) => m.iter().collect(),",
     "SigMap::Tree(m) => {\n                let v: Vec<_> = m.iter().collect();\n"
     "                (0..v.len()).map(|i| (v[i].0, v[(i + 1) % v.len()].1)).collect()\n            }"),
    ("T02", "tree entry gets its own key bytes as the signature (key address read as signature)", "sigmap.rs",
     "SigMap::Tree(m) => m.iter().collect(),",
     "SigMap::Tree(m) => m\n                .iter()\n                .map(|(k, _)| {\n"
     "                    let s: Signature = std::array::from_fn(|i| k[i % 20]);\n"
     "                    (k, &*Box::leak(Box::new(s)))\n                })\n                .collect(),"),
    ("T03", "tree entries from the 65th on get the signature of entry i-64", "sigmap.rs",
     "SigMap::Tree(m) => m.iter().collect(),",
     "SigMap::Tree(m) => {\n                let v: Vec<_> = m.iter().collect();\n"
     "                (0..v.len()).map(|i| (v[i].0, v[if i >= 64 { i - 64 } else { i }].1)).collect()\n            }"),
    ("T04", "ring row gets the signature of the next row (row stride off by one)", "sigmap.rs",
     "(&r.key, &r.sig)", "(&r.key, &rows[(head + i + 1) % rows.len()].sig)"),
    ("T05", "a bad signature is never refused when the certificate has more than 64 signatures", "verifier.rs",
     "if !signer_check(primitives, 1, &frame, key, signature, set) {",
     "if !signer_check(primitives, 1, &frame, key, signature, set) && cert.sigs.len() <= 64 {"),
    # collect.rs: 0x4e00160
    ("C01", "collector accepts only non-members", "collect.rs", "if !set.stakes.contains(key) {", "if set.stakes.contains(key) {"),
    ("C02", "collector returns an empty signer set", "collect.rs", "signers.insert(*key);", ""),
    # stake.rs: membership and the 0x4d3e1a0 test
    ("S01", "ring search: seam equality is a miss", "stake.rs", "Ordering::Equal => true,", "Ordering::Equal => false,"),
    ("S02", "ring search: no back slice is a miss", "stake.rs", "None => search(front),", "None => false,"),
    ("S03", "stake test: 3*signed >= 2*total", "stake.rs",
     "3 * u128::from(signed) > 2 * u128::from(total)", "3 * u128::from(signed) >= 2 * u128::from(total)"),
    ("S04", "stake test: signed sum wraps instead of saturating", "stake.rs",
     ".filter_map(|k| m.get(k)).fold(0u64, |a, w| a.saturating_add(*w));",
     ".filter_map(|k| m.get(k)).fold(0u64, |a, w| a.wrapping_add(*w));"),
    ("S05", "stake test: 3*signed > 3*total", "stake.rs",
     "3 * u128::from(signed) > 2 * u128::from(total)", "3 * u128::from(signed) > 3 * u128::from(total)"),
    # quorum.rs: 0x595bc40
    ("Q01", "non-finite fraction counts as 0.7", "quorum.rs", "return 1.0;", "return 0.7;"),
    ("Q02", "upper clamp 0.8", "quorum.rs", "if 0.7 < t { 0.7 } else { t }", "if 0.8 < t { 0.8 } else { t }"),
    ("Q03", "max finite double treated as non-finite", "quorum.rs", "> 0x7fef_ffff_ffff_ffff {", ">= 0x7fef_ffff_ffff_ffff {"),
    ("Q04", "zero fraction no longer returns true at once", "quorum.rs", "if f == 0.0 {", "if false {"),
    ("Q05", "count test >=", "quorum.rs", "(count as f64) > f *", "(count as f64) >= f *"),
    ("Q06", "count test uses the validator tree size, not the stored count", "quorum.rs",
     "set.validator_count as f64", "set.validators.len() as f64"),
    ("Q07", "stake test skipped", "quorum.rs", "if !set.stakes.stake_test(&keys) {", "if false {"),
    # signer.rs: 0x57e8bd0
    ("K01", "signer check skips the membership test", "signer.rs", "if !set.stakes.contains(address) {", "if false {"),
    ("K02", "signer check accepts any successful recovery", "signer.rs", ".as_ref() == Some(address)", ".is_some()"),
    ("K03", "digest variant forced to 0", "signer.rs", "primitives.digest(variant, frame)", "primitives.digest(0, frame)"),
    # history.rs: 0x595e5c0
    ("H01", "warning needs r > limit (equality no longer warns)", "history.rs",
     "round >= self.base.saturating_add(2000).max(", "round > self.base.saturating_add(2000).max("),
    ("H02", "lookup round: r <= min(base+2000, MAX) keeps the base", "history.rs",
     "if round < self.base.saturating_add(2000) { self.base }", "if round <= self.base.saturating_add(2000) { self.base }"),
    ("H03", "lookup round subtracts 201", "history.rs", "round.wrapping_sub(200)", "round.wrapping_sub(201)"),
    ("H04", "lookup round without the max against the base", "history.rs",
     "self.base.max(round.wrapping_sub(200))", "round.wrapping_sub(200)"),
    ("H05", "limit adds 200 to the execution round", "history.rs", "self.execution.saturating_add(201)", "self.execution.saturating_add(200)"),
    ("H06", "warning counter saturates instead of wrapping", "history.rs",
     "self.warnings.get().wrapping_add(1)", "self.warnings.get().saturating_add(1)"),
    ("H07", "tree search excludes the lookup round", "history.rs", "m.range(..=q)", "m.range(..q)"),
    ("H08", "ring search excludes the lookup round", "history.rs", "at(i).0 <= q", "at(i).0 < q"),
    ("H09", "ring constructor accepts equal rounds", "history.rs", ".0 < rows[(head + i) % cap].0", ".0 <= rows[(head + i) % cap].0"),
    ("H10", "ring search ignores the head", "history.rs", "&rows[(head + i) % rows.len()]", "&rows[i % rows.len()]"),
    ("H11", "no warning is ever counted", "history.rs", "if self.warns(round) {", "if false {"),
    # verifier.rs: 0x595f880
    ("V01", "provider asked about f38 instead of f40", "verifier.rs", "let round = cert.f40;", "let round = cert.f38;"),
    ("V02", "signature check uses variant 0", "verifier.rs", "signer_check(primitives, 1, &frame", "signer_check(primitives, 0, &frame"),
    ("V03", "quorum rejection tag 0x06", "verifier.rs", "Rejection::QuorumNotReached => 0x07", "Rejection::QuorumNotReached => 0x06"),
    ("V04", "quorum skipped", "verifier.rs", "if !quorum(ctx.quorum_fraction_bits, set, &signers) {", "if false {"),
    ("V05", "frame carries f40 where f38 belongs and the reverse", "verifier.rs",
     "            f38: cert.f38,\n            f40: cert.f40,\n", "            f38: cert.f40,\n            f40: cert.f38,\n"),
    ("V06", "frame hash left zero", "verifier.rs", "hash: cert.hash,", "hash: [0; 32],"),
    ("V07", "frame signer left zero", "verifier.rs", "signer: *key,", "signer: [0; 20],"),
    ("V08", "bad signature ignored", "verifier.rs", "return Verdict::Rejected(Rejection::BadSignature);", "{}"),
    ("V09", "only the first entry is checked", "verifier.rs", "cert.sigs.entries() {", "cert.sigs.entries().into_iter().take(1) {"),
    ("V10", "entries checked in reverse order", "verifier.rs", "cert.sigs.entries() {", "cert.sigs.entries().into_iter().rev() {"),
    ("V11", "unknown signer reports the wrong tag", "verifier.rs", "Rejection::UnknownSigner { .. } => 0x2c", "Rejection::UnknownSigner { .. } => 0x2b"),
    ("V12", "missing stake set reports the wrong tag", "verifier.rs", "Rejection::NoStakeSet { .. } => 0x28", "Rejection::NoStakeSet { .. } => 0x29"),
    # round 4: keccak.rs (hasher 0x5cda910 / 0x5cdad40 and the permutation)
    ("KC01", "hasher delimiter 0x06 (SHA3-256) instead of 0x01", "keccak.rs", "Self::with_delimiter(0x01)", "Self::with_delimiter(0x06)"),
    ("KC02", "closing 0x80 padding bit in byte rate-2", "keccak.rs", "self.buffer[RATE - 1] ^= 0x80;", "self.buffer[RATE - 2] ^= 0x80;"),
    ("KC03", "absorb: a block is processed only when more than the room is left", "keccak.rs",
     "while data.len() >= RATE - offset {", "while data.len() > RATE - offset {"),
    ("KC04", "theta rotates by 2", "keccak.rs", "c[(x + 1) % 5].rotate_left(1)", "c[(x + 1) % 5].rotate_left(2)"),
    ("KC05", "one rotation offset 45 instead of 44", "keccak.rs", "36, 44, 6,", "36, 45, 6,"),
    ("KC06", "last round constant off by one", "keccak.rs", "0x8000_0000_8000_8008,", "0x8000_0000_8000_8009,"),
    ("KC07", "chi uses lane x+3", "keccak.rs", "& b[(x + 2) % 5 + 5 * y]", "& b[(x + 3) % 5 + 5 * y]"),
    ("KC08", "output taken from buffer bytes 1..33", "keccak.rs", "out.copy_from_slice(&self.buffer[..32]);", "out.copy_from_slice(&self.buffer[1..33]);"),
    ("KC09", "partial block forgets the previous offset", "keccak.rs", "self.offset = offset + data.len();", "self.offset = data.len();"),
    # round 4: digest.rs (digest builder 0x57e8d40, serializers 0x5823db0 / 0x5966b90 / 0x5822910)
    ("DG01", "prefix text differs in its last byte", "digest.rs", 'b"Hyperliquid Consensus Payload"', 'b"Hyperliquid Consensus Payloae"'),
    ("DG02", "message tag byte 2 instead of 1", "digest.rs", "let mut out = vec![0x01];", "let mut out = vec![0x02];"),
    ("DG03", "signer address written after the five words", "digest.rs",
     "    out.extend_from_slice(&frame.signer);\n    for w in [frame.pair[0], frame.pair[1], frame.f30, frame.f38, frame.f40] {\n        put_varint(&mut out, w);\n    }\n",
     "    for w in [frame.pair[0], frame.pair[1], frame.f30, frame.f38, frame.f40] {\n        put_varint(&mut out, w);\n    }\n    out.extend_from_slice(&frame.signer);\n"),
    ("DG04", "words f38 and f40 written in swapped order", "digest.rs",
     "[frame.pair[0], frame.pair[1], frame.f30, frame.f38, frame.f40]", "[frame.pair[0], frame.pair[1], frame.f30, frame.f40, frame.f38]"),
    # DG05..DG09 and DG11 edit the varint writer the crate now reuses (a copy of it in the scratch tree)
    ("DG05", "varint one-byte form below 250 instead of 251 (reused writer)", VARINT, "if value < 251 {", "if value < 250 {"),
    ("DG06", "varint two-byte form up to and including 65536 (reused writer)", VARINT, "= if value < 65_536 {", "= if value <= 65_536 {"),
    ("DG07", "varint four-byte form up to and including 2^32 (reused writer)", VARINT,
     "} else if value < (1_u64 << 32) {", "} else if value <= (1_u64 << 32) {"),
    ("DG08", "varint two-byte marker 0xfa (reused writer)", VARINT, "(251, 2)", "(250, 2)"),
    ("DG09", "varint payload big endian (reused writer)", VARINT, "&value.to_le_bytes()[..width]", "&value.to_be_bytes()[8 - width..]"),
    ("DG10", "hash bytes left out of the message", "digest.rs", "    out.extend_from_slice(&frame.hash);\n", ""),
    ("DG11", "varint eight-byte marker 0xfc (reused writer)", VARINT, "(253, 8)", "(252, 8)"),
    ("DG12", "digest hashes the message without the prefix", "digest.rs", "h.update(&preimage(frame));", "h.update(&serialize_message(frame));"),
    # round 4: recover.rs (recovery wrapper 0x1536a90)
    ("RV01", "v = 27 gives recovery id 1", "recover.rs", "0 | 27 => Some(0),", "0 | 27 => Some(1),"),
    ("RV02", "v >= 35 gives id v & 1 instead of (!v) & 1", "recover.rs", "_ => Some(!v & 1),", "_ => Some(v & 1),"),
    ("RV03", "v = 29 is accepted", "recover.rs", "2..=26 | 29..=34 => None,", "2..=26 | 30..=34 => None,"),
    ("RV04", "r is not byte reversed", "recover.rs", "reversed(&signature[0..32]);", "signature[0..32].try_into().unwrap();"),
    ("RV05", "s is taken from bytes 31..63", "recover.rs", "reversed(&signature[32..64]);", "reversed(&signature[31..63]);"),
    ("RV06", "address is bytes 11..31 of the hash", "recover.rs", "keccak256(&key)[12..32]", "keccak256(&key)[11..31]"),
    ("RV07", "bad recovery byte reports error kind 3", "recover.rs", "RecoverError::BadRecoveryByte => 6,", "RecoverError::BadRecoveryByte => 3,"),
    ("RV08", "a curve failure is turned into an all-zero key", "recover.rs", ".ok_or(RecoverError::CurveFailure)?;", ".unwrap_or([0; 64]);"),
    ("RV09", "a bad recovery byte still calls the curve routine with id 0", "recover.rs",
     ".ok_or(RecoverError::BadRecoveryByte)?;", ".unwrap_or(0);"),
    ("RV10", "r and s handed over swapped", "recover.rs", "curve.recover(&r, &s, id, digest)", "curve.recover(&s, &r, id, digest)"),
    # round 4: primitives.rs
    ("PR01", "another message variant is no longer refused", "primitives.rs",
     'assert_eq!(variant, VARIANT, "only message variant 1 was read");', "let _ = variant;"),
]


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def inputs_of(root):
    paths = []
    for c in CRATES:
        base = os.path.join(root, "src", c)
        for d, dirs, files in os.walk(base):
            dirs[:] = sorted(x for x in dirs if x != "target")
            paths += [os.path.join(d, f) for f in sorted(files)]
    pk = os.path.join(root, PACKET)
    paths += [os.path.join(pk, n) for n in sorted(os.listdir(pk)) if n.startswith("cases")]
    return paths


def cargo(tmp, env, *extra):
    cmd = ["cargo", "test", "--offline", "--locked", "--manifest-path",
           os.path.join(tmp, "src/node115-nested-certificate-decision/Cargo.toml")] + list(extra)
    try:
        # one stream, so that the "Running <test binary>" lines stay in front of that binary's results
        r = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           errors="replace", timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, "timeout after %d s" % TIMEOUT
    except OSError as e:
        return 127, "cannot run cargo: %r" % (e,)
    return r.returncode, r.stdout


def parse_tests(text):
    """{ 'binary::test': 'ok'|'FAILED'|'ignored' } from a `cargo test` log."""
    results, current = {}, "?"
    for line in text.splitlines():
        m = re.match(r"^\s+(?:Running|Doc-tests) (.+?)(?: \(.*\))?$", line)
        if m:
            current = m.group(1)
            continue
        m = re.match(r"^test (\S+?)(?: - should panic)? \.\.\. (ok|FAILED|ignored)", line)
        if m:
            results[current + "::" + m.group(1)] = m.group(2)
    return results


def parse_corpora(text):
    return sorted(set(re.findall(r"^CORPUS (\w+) cases=\d+ mismatches=([1-9]\d*)", text, re.M)))


def prepare_outdir(outdir, root):
    if not outdir:
        sys.exit("--outdir is required: results are written only to a new directory")
    out = os.path.realpath(outdir)
    guarded = [os.path.realpath(os.path.join(root, "src", c)) for c in CRATES] + [os.path.realpath(os.path.join(root, PACKET))]
    for g in guarded:
        if out == g or out.startswith(g + os.sep):
            sys.exit("--outdir must not be inside " + g)
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        sys.exit("--outdir must not exist yet or be an empty directory: " + outdir)
    os.makedirs(out, exist_ok=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--outdir")
    ap.add_argument("--only")
    ap.add_argument("--add-mutant", action="append", default=[])
    args = ap.parse_args()
    root = args.root
    out = prepare_outdir(args.outdir, root)
    mutants = list(MUTANTS)
    for spec in args.add_mutant:
        mid, fname, old, new = spec.split("::")
        mutants.append((mid, "added on the command line", fname, old, new))
    if args.only:
        want = args.only.split(",")
        unknown = [w for w in want if w not in [m[0] for m in mutants]]
        if unknown:
            sys.exit("unknown mutant ids: " + ",".join(unknown))
        mutants = [m for m in mutants if m[0] in want]
    before = {p: sha(p) for p in inputs_of(root)}
    lines = []

    def say(s):
        lines.append(s)
        print(s, flush=True)

    rows = ["id\tchange\tfile\tbuilt\tresults_complete\tkilled\tfailing_tests\tcorpora_with_mismatches\tstatus"]
    problems = 0
    with tempfile.TemporaryDirectory() as tmp:
        for c in CRATES:
            shutil.copytree(os.path.join(root, "src", c), os.path.join(tmp, "src", c), ignore=shutil.ignore_patterns("target"))
        os.makedirs(os.path.join(tmp, PACKET))
        for name in os.listdir(os.path.join(root, PACKET)):
            if name.startswith("cases"):
                shutil.copy(os.path.join(root, PACKET, name), os.path.join(tmp, PACKET, name))
        env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(tmp, "target"))

        code, text = cargo(tmp, env, "--no-run")
        if code != 0:
            say("baseline control failed: the unmodified crate does not build")
            say(text[-1500:])
            finish(out, lines, rows, 1)
        code, text = cargo(tmp, env, "--no-fail-fast")
        inventory = parse_tests(text)
        if code != 0 or not inventory or any(v != "ok" for v in inventory.values()):
            say("baseline control failed: the unmodified crate does not pass all of its tests")
            say(text[-1500:])
            finish(out, lines, rows, 1)
        say("baseline: build ok, %d tests ok" % len(inventory))

        for mid, desc, fname, old, new in mutants:
            path = os.path.join(tmp, SRC, fname)
            with open(path, encoding="utf-8") as f:
                src = f.read()
            if src.count(old) != 1:
                say("%s: the edit text occurs %d times in %s, expected exactly once" % (mid, src.count(old), fname))
                rows.append("\t".join([mid, desc, fname, "-", "-", "-", "-", "-", "ERROR bad edit"]))
                problems += 1
                continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(src.replace(old, new))
            try:
                bcode, btext = cargo(tmp, env, "--no-run")
                built = bcode == 0
                results, failed, corp, status, complete = {}, [], [], "", False
                if not built:
                    status = "ERROR build failed (exit %d), not a kill" % bcode
                else:
                    tcode, ttext = cargo(tmp, env, "--no-fail-fast")
                    results = parse_tests(ttext)
                    complete = all(k in results for k in inventory)
                    failed = sorted(k for k, v in results.items() if v == "FAILED")
                    corp = ["%s:%s" % c for c in parse_corpora(ttext)]
                    if not complete:
                        status = "ERROR results missing for %d tests (cargo exit %d)" % (sum(k not in results for k in inventory), tcode)
                    elif failed:
                        status = "killed"
                    elif tcode != 0:
                        status = "ERROR cargo exit %d without a failing test" % tcode
                    else:
                        status = "SURVIVED"
            finally:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(src)
            if status != "killed":
                problems += 1
            rows.append("\t".join([mid, desc, fname, "yes" if built else "no", "yes" if complete else "no",
                                   "yes" if status == "killed" else "no", ",".join(failed) or "-", ",".join(corp) or "-", status]))
            say(rows[-1])
        say("mutants %d, not killed or in error %d" % (len(mutants), problems))
    after = {p: sha(p) for p in inputs_of(root)}
    if after != before:
        say("FAIL an input file of the repository tree changed during the run")
        problems += 1
    finish(out, lines, rows, 1 if problems else 0)


def finish(out, lines, rows, code):
    with open(os.path.join(out, "mutations.tsv"), "w", newline="\n") as f:
        f.write("\n".join(rows) + "\n")
    with open(os.path.join(out, "report.txt"), "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    sys.exit(code)


if __name__ == "__main__":
    main()
