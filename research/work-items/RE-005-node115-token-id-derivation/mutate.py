#!/usr/bin/env python3
"""Mutation check of the node115-token-id crate (RE-005 token-id packet).

Copies the crate, the existing permutation source and the frozen corpus into a NEW --outdir, applies
one source edit per mutant to the COPY, and runs the crate's tests. Nothing outside --outdir is
written (refused if it exists or lies inside this packet or the crate); the input tree is only read.

Each mutant is built (`cargo test --no-run`) and run (`cargo test`) in separate steps, in its own
target directory. A mutant counts as killed only if the build succeeded, the run reported FAILED
tests, and the named test of the mutant is among them. A build error, a cargo that cannot be started,
a timeout, or a run that fails without any FAILED test is an environment problem: exit code 2, never
a kill. Exit codes: 0 every mutant killed by its named test, 1 a mutant survived or was killed by the
wrong test, 2 environment error or failing baseline.

  mutate.py --outdir NEW [--cargo cargo]
  mutate.py --outdir NEW --selftest      controls: baseline first, then a survivor, a build error, no cargo
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, '..', '..', '..'))
CRATE = os.path.join(ROOT, 'src', 'node115-token-id')
PACKET_REL = os.path.relpath(HERE, ROOT)
CORPUS_TEST = 'corpus_matches_frozen_oracle'
KECCAK_TEST = 'keccak256_published_vectors_and_chunking'
LIMIT_TEST = 'selected_check_index_limit_runs_before_id_derivation'
DUPLICATE_TEST = 'selected_check_duplicate_id_is_key_membership'
ANCHOR_TEST = 'scout_anchor_by_hand'

L, K, R = 'src/lib.rs', 'src/keccak.rs', 'src/registry.rs'
# (id, file, old text (must occur exactly once), new text, test that must fail)
MUTANTS = [
    ('array_count_93', L, 'out.push(0x92);', 'out.push(0x93);', ANCHOR_TEST),
    ('map_count_84', L, 'out.push(0x83);', 'out.push(0x84);', ANCHOR_TEST),
    ('key_name_typo', L, 'put_str(&mut out, b"name")?;', 'put_str(&mut out, b"nome")?;', CORPUS_TEST),
    ('decimals_order_swapped', L,
     '    put_str(&mut out, b"szDecimals")?;\n    put_uint(&mut out, u64::from(spec.sz_decimals));\n'
     '    put_str(&mut out, b"weiDecimals")?;\n    put_uint(&mut out, u64::from(spec.wei_decimals));\n',
     '    put_str(&mut out, b"weiDecimals")?;\n    put_uint(&mut out, u64::from(spec.wei_decimals));\n'
     '    put_str(&mut out, b"szDecimals")?;\n    put_uint(&mut out, u64::from(spec.sz_decimals));\n', CORPUS_TEST),
    ('sz_value_from_wei', L, 'put_uint(&mut out, u64::from(spec.sz_decimals));',
     'put_uint(&mut out, u64::from(spec.wei_decimals));', CORPUS_TEST),
    ('str_fix_boundary_31', L, 'if len < 0x20 {', 'if len < 0x1f {', CORPUS_TEST),
    ('str_d9_boundary_256', L, '} else if len < 0x100 {', '} else if len <= 0x100 {', CORPUS_TEST),
    ('str_da_boundary_65536', L, '} else if len < 0x1_0000 {', '} else if len <= 0x1_0000 {', CORPUS_TEST),
    ('str_fixstr_marker', L, '0xa0 | len as u8', '0x80 | len as u8', CORPUS_TEST),
    ('str_db_marker', L, '[0xdb, be[4],', '[0xdc, be[4],', CORPUS_TEST),
    ('uint_fixint_boundary_128', L, 'if value < 0x80 {', 'if value <= 0x80 {', CORPUS_TEST),
    ('uint_cc_boundary_256', L, '} else if value < 0x100 {', '} else if value <= 0x100 {', CORPUS_TEST),
    ('uint_cd_boundary_65536', L, '} else if value < 0x1_0000 {', '} else if value <= 0x1_0000 {', CORPUS_TEST),
    ('uint_ce_boundary_2_32', L, '} else if value <= u64::from(u32::MAX) {', '} else if value < u64::from(u32::MAX) {', CORPUS_TEST),
    ('uint_cc_marker', L, '[0xcc, be[7]]', '[0xd0, be[7]]', CORPUS_TEST),
    ('uint_cf_marker', L, 'out.push(0xcf);', 'out.push(0xd3);', CORPUS_TEST),
    ('uint_little_endian', L, 'let be = value.to_be_bytes();', 'let be = value.to_le_bytes();', CORPUS_TEST),
    ('id_is_digest_tail', L, 'id.copy_from_slice(&full[..ID_LEN]);', 'id.copy_from_slice(&full[32 - ID_LEN..]);', CORPUS_TEST),
    ('name_limit_removed', L, '} else if len <= u64::from(u32::MAX) {', '} else if len <= u64::MAX {',
     'tests::name_length_limit_is_32_bits'),
    ('keccak_sha3_delimiter', K, 'const DELIMITER: u8 = 0x01;', 'const DELIMITER: u8 = 0x06;', KECCAK_TEST),
    ('keccak_rate_168', K, 'const RATE: usize = 136;', 'const RATE: usize = 168;', KECCAK_TEST),
    ('keccak_pad_bit', K, 'self.buffer[RATE - 1] ^= 0x80;', 'self.buffer[RATE - 1] ^= 0x40;', KECCAK_TEST),
    # the published vectors are shorter than one block; only the corpus reaches multi-block input
    ('keccak_skip_block_permute', K, '                permute_bytes(&mut self.buffer);\n                self.offset = 0;',
     '                self.offset = 0;', CORPUS_TEST),
    ('keccak_overwrite_not_xor', K, '*byte ^= new;', '*byte = *new;', CORPUS_TEST),
    ('keccak_delimiter_at_zero', K, 'self.buffer[self.offset] ^= DELIMITER;', 'self.buffer[0] ^= DELIMITER;', KECCAK_TEST),
    ('keccak_output_window', K, 'out.copy_from_slice(&self.buffer[..32]);', 'out.copy_from_slice(&self.buffer[8..40]);', KECCAK_TEST),
    ('registry_max_index', R, 'pub const MAX_INDEX: u64 = 0x1869e;', 'pub const MAX_INDEX: u64 = 0x1869f;', LIMIT_TEST),
    ('registry_gate_off_by_one', R, 'if index > MAX_INDEX {', 'if index >= MAX_INDEX {', LIMIT_TEST),
    ('registry_never_inserts', R, 'if !self.ids.insert(id) {', 'if self.ids.contains(&id) {', DUPLICATE_TEST),
]
# controls only used by --selftest
SURVIVOR = ('equivalent_edit', K, 'input.len().min(RATE - self.offset)', 'input.len().min(RATE - self.offset + 0)', CORPUS_TEST)
BROKEN = ('does_not_compile', K, 'const RATE: usize = 136;', 'const RATE: usize = "136";', CORPUS_TEST)
# one flipped bit (0 -> 1 in the last hex digit) in the frozen corpus must fail the corpus test
CORPUS_BIT_FLIPS = [
    ('corpus_digest_bit', '@corpus.tsv', '9058f4586f457c793b70c2871d15c2d5aeaff298b6045f98bd02ee96b891dd40',
     '9058f4586f457c793b70c2871d15c2d5aeaff298b6045f98bd02ee96b891dd41', CORPUS_TEST),
    ('corpus_preimage_bit', '@corpus.tsv', '9283a46e616d65a158aa737a446563696d616c7306ab776569446563696d616c730800',
     '9283a46e616d65a158aa737a446563696d616c7306ab776569446563696d616c730801', CORPUS_TEST),
]


class EnvError(Exception):
    pass


def new_outdir(path):
    out = os.path.realpath(path)
    for guarded in (HERE, CRATE):
        if out == guarded or out.startswith(guarded + os.sep):
            raise EnvError('refusing --outdir inside the packet or the crate: ' + out)
    if os.path.lexists(path):
        raise EnvError('refusing existing --outdir: ' + out)
    os.makedirs(out)
    return out


def sh(cmd, cwd, timeout=300):
    try:
        run = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvError('cannot run %s: %s' % (cmd[0], exc))
    return run.returncode, run.stdout + run.stderr


def prepare_base(out):
    base = os.path.join(out, 'base')
    shutil.copytree(CRATE, os.path.join(base, 'src', 'node115-token-id'), ignore=shutil.ignore_patterns('target'))
    os.makedirs(os.path.join(base, 'src', 'node115-sponge-permutation'))
    shutil.copy(os.path.join(ROOT, 'src', 'node115-sponge-permutation', 'lib.rs'),
                os.path.join(base, 'src', 'node115-sponge-permutation', 'lib.rs'))
    os.makedirs(os.path.join(base, PACKET_REL))
    for name in ('corpus.tsv', 'wrong-variants.tsv'):
        shutil.copy(os.path.join(HERE, name), os.path.join(base, PACKET_REL, name))
    return base


def cargo(cargo_bin, tree, target, extra):
    manifest = os.path.join(tree, 'src', 'node115-token-id', 'Cargo.toml')
    return [cargo_bin, 'test', '--offline', '--locked', '--manifest-path', manifest, '--target-dir', target] + extra


def evaluate(base, mutant, cargo_bin, work):
    """Returns (status, failed tests). Raises EnvError for anything that is not a test verdict."""
    mid, rel, old, new, expect = mutant
    tree = os.path.join(work, mid)
    shutil.copytree(base, tree)
    # a leading '@' names a file of the packet copy (corpus corruption controls) instead of a crate file
    path = os.path.join(tree, PACKET_REL, rel[1:]) if rel.startswith('@') else os.path.join(tree, 'src', 'node115-token-id', rel)
    text = open(path).read()
    if text.count(old) != 1:
        raise EnvError('%s: edit text occurs %d times in %s' % (mid, text.count(old), rel))
    with open(path, 'w') as fh:
        fh.write(text.replace(old, new))
    target = os.path.join(tree, 'target')
    rc, log = sh(cargo(cargo_bin, tree, target, ['--no-run']), tree)
    if rc != 0:
        return 'BUILD_ERROR', [log.strip().splitlines()[-1] if log.strip() else '']
    rc, log = sh(cargo(cargo_bin, tree, target, ['--no-fail-fast']), tree)
    failed = re.findall(r'^test (\S+) \.\.\. FAILED$', log, re.M)
    if rc == 0:
        return 'SURVIVED', []
    if not failed:
        raise EnvError('%s: tests failed without a FAILED test line' % mid)
    return ('KILLED' if expect in failed else 'KILLED_BY_OTHER_TEST'), failed


def baseline(base, cargo_bin, work):
    tree = os.path.join(work, 'baseline')
    shutil.copytree(base, tree)
    rc, log = sh(cargo(cargo_bin, tree, os.path.join(tree, 'target'), []), tree)
    if rc != 0:
        raise EnvError('baseline tests do not pass, mutants would mean nothing:\n' + log[-600:])
    return sorted(re.findall(r'^test (\S+) \.\.\. ok$', log, re.M))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--cargo', default='cargo')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    try:
        out = new_outdir(args.outdir)
        base = prepare_base(out)
        work = os.path.join(out, 'work')
        os.makedirs(work)
        tests = baseline(base, args.cargo, work)
        print('baseline passes: %d tests' % len(tests))
        if args.selftest:
            return selftest(base, args.cargo, work, out)
        rows, bad = [], 0
        for m in MUTANTS:
            status, failed = evaluate(base, m, args.cargo, work)
            if status == 'BUILD_ERROR':
                raise EnvError('%s does not compile: %s' % (m[0], failed))
            rows.append('%s\t%s\t%s\t%s\t%s' % (m[0], m[1], m[4], status, ','.join(failed)))
            bad += status != 'KILLED'
            print('%-28s %s' % (m[0], status))
        with open(os.path.join(out, 'mutants.tsv'), 'x') as fh:
            fh.write('mutant\tfile\texpected_test\tstatus\tfailed_tests\n' + '\n'.join(rows) + '\n')
        print('%d mutants, %d killed by their named test, %d not' % (len(MUTANTS), len(MUTANTS) - bad, bad))
        return 1 if bad else 0
    except EnvError as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2


def selftest(base, cargo_bin, work, out):
    status, _ = evaluate(base, SURVIVOR, cargo_bin, work)
    assert status == 'SURVIVED', status
    status, detail = evaluate(base, BROKEN, cargo_bin, work)
    assert status == 'BUILD_ERROR', status
    try:
        evaluate(base, MUTANTS[0], os.path.join(out, 'no-such-cargo'), work + '-nocargo')
        raise AssertionError('missing cargo was not an error')
    except (EnvError, FileNotFoundError):
        pass
    status, _ = evaluate(base, MUTANTS[0], cargo_bin, work + '-again')
    assert status == 'KILLED', status
    for flip in CORPUS_BIT_FLIPS:
        status, _ = evaluate(base, flip, cargo_bin, work + '-corpus')
        assert status == 'KILLED', (flip[0], status)
    print('selftest ok: equivalent edit SURVIVED, uncompilable edit BUILD_ERROR (not a kill), '
          'missing cargo is an environment error, a real mutant is KILLED, %d corpus bit flips KILLED' % len(CORPUS_BIT_FLIPS))
    return 0


if __name__ == '__main__':
    sys.exit(main())
