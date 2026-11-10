#!/usr/bin/env python3
"""Mutation check of the node115-vault-address crate (RE-005 vault-address packet).

Copies the crate, the existing permutation source and the frozen corpus into a NEW --outdir, applies
one source edit per mutant to the COPY, and runs the crate's tests. Nothing outside --outdir is
written (refused if it exists or lies inside this packet or the crate); the input tree is only read.

Each mutant is built (`cargo test --no-run`) and run (`cargo test --no-fail-fast`) in separate steps, in
its own target directory. A mutant counts as killed only if the build succeeded, the run reported FAILED
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
CRATE = os.path.join(ROOT, 'src', 'node115-vault-address')
PACKET_REL = os.path.relpath(HERE, ROOT)
CORPUS_TEST = 'corpus_matches_frozen_oracle'
KECCAK_TEST = 'keccak256_published_vectors_and_chunking'
ANCHOR_TEST = 'scout_anchor_by_hand'
FEE_TEST = 'max_usdc_fee_has_no_influence_on_the_derivation'
NAME_TEST = 'caller_name_limit_and_its_precedence_over_the_amount_check'
AMOUNT_TEST = 'caller_amount_bound_and_which_value_is_reported_first'
LIMIT_TEST = 'tests::string_length_limit_is_32_bits'
ORDER_TEST = 'request_map_keys_follow_the_order_extracted_from_the_binary'

L, K = 'src/lib.rs', 'src/keccak.rs'
# (id, file, old text (must occur exactly once), new text, test that must fail)
MUTANTS = [
    ('array_count_93', L, 'out.push(0x92);', 'out.push(0x93);', ANCHOR_TEST),
    ('map_count_85', L, 'out.push(0x84);', 'out.push(0x85);', ANCHOR_TEST),
    ('creator_prefix_missing', L, 'text.push_str("0x");', 'text.push_str("");', ANCHOR_TEST),
    ('creator_upper_case_digits', L, 'b"0123456789abcdef"', 'b"0123456789ABCDEF"', CORPUS_TEST),
    ('key_name_typo', L, 'put_str(&mut out, b"name")?;', 'put_str(&mut out, b"nome")?;', ANCHOR_TEST),
    ('key_description_typo', L, 'put_str(&mut out, b"description")?;', 'put_str(&mut out, b"descriptio")?;', ANCHOR_TEST),
    ('key_initial_usd_typo', L, 'put_str(&mut out, b"initialUsd")?;', 'put_str(&mut out, b"initialUSD")?;', ANCHOR_TEST),
    ('key_nonce_typo', L, 'put_str(&mut out, b"nonce")?;', 'put_str(&mut out, b"nonces")?;', ANCHOR_TEST),
    ('usd_value_from_nonce', L, 'put_uint(&mut out, request.initial_usd);', 'put_uint(&mut out, request.nonce);', ANCHOR_TEST),
    ('description_before_name', L,
     '    put_str(&mut out, b"name")?;\n    put_str(&mut out, request.name.as_bytes())?;\n'
     '    put_str(&mut out, b"description")?;\n    put_str(&mut out, request.description.as_bytes())?;\n',
     '    put_str(&mut out, b"description")?;\n    put_str(&mut out, request.description.as_bytes())?;\n'
     '    put_str(&mut out, b"name")?;\n    put_str(&mut out, request.name.as_bytes())?;\n', ORDER_TEST),
    ('nonce_before_initial_usd', L,
     '    put_str(&mut out, b"initialUsd")?;\n    put_uint(&mut out, request.initial_usd);\n'
     '    put_str(&mut out, b"nonce")?;\n    put_uint(&mut out, request.nonce);\n',
     '    put_str(&mut out, b"nonce")?;\n    put_uint(&mut out, request.nonce);\n'
     '    put_str(&mut out, b"initialUsd")?;\n    put_uint(&mut out, request.initial_usd);\n', ORDER_TEST),
    ('fee_key_appended', L, 'put_uint(&mut out, request.nonce);',
     'put_uint(&mut out, request.nonce);\n    if let Some(fee) = request.max_usdc_fee {\n        put_str(&mut out, b"maxUsdcFee")?;\n        put_uint(&mut out, fee);\n    }',
     FEE_TEST),
    ('str_fix_boundary_31', L, 'if len < 0x20 {', 'if len < 0x1f {', CORPUS_TEST),
    ('str_d9_boundary_256', L, '} else if len < 0x100 {', '} else if len <= 0x100 {', CORPUS_TEST),
    ('str_da_boundary_65536', L, '} else if len < 0x1_0000 {', '} else if len <= 0x1_0000 {', CORPUS_TEST),
    ('str_fixstr_marker', L, '0xa0 | len as u8', '0x80 | len as u8', ANCHOR_TEST),
    ('str_db_marker', L, 'out.extend_from_slice(&[0xdb,', 'out.extend_from_slice(&[0xdc,', CORPUS_TEST),
    ('uint_fixint_boundary_128', L, 'if value < 0x80 {', 'if value <= 0x80 {', CORPUS_TEST),
    ('uint_cc_boundary_256', L, '} else if value < 0x100 {', '} else if value <= 0x100 {', CORPUS_TEST),
    ('uint_cd_boundary_65536', L, '} else if value < 0x1_0000 {', '} else if value <= 0x1_0000 {', CORPUS_TEST),
    ('uint_ce_boundary_2_32', L, '} else if value <= u64::from(u32::MAX) {', '} else if value < u64::from(u32::MAX) {', CORPUS_TEST),
    ('uint_cc_marker', L, '[0xcc, be[7]]', '[0xd0, be[7]]', CORPUS_TEST),
    ('uint_cf_marker', L, 'out.push(0xcf);', 'out.push(0xd3);', CORPUS_TEST),
    ('uint_little_endian', L, 'let be = value.to_be_bytes();', 'let be = value.to_le_bytes();', CORPUS_TEST),
    ('address_is_digest_tail', L, 'address.copy_from_slice(&digest[..ADDRESS_LEN]);',
     'address.copy_from_slice(&digest[32 - ADDRESS_LEN..]);', ANCHOR_TEST),
    ('string_limit_removed', L, '} else if len <= u64::from(u32::MAX) {', '} else if len <= u64::MAX {', LIMIT_TEST),
    ('caller_name_limit_101', L, 'pub const NAME_LEN_LIMIT: usize = 100;', 'pub const NAME_LEN_LIMIT: usize = 101;', NAME_TEST),
    ('caller_name_check_removed', L, 'if request.name.len() > NAME_LEN_LIMIT {', 'if false && request.name.len() > NAME_LEN_LIMIT {', NAME_TEST),
    ('caller_amount_bound_off_by_one', L, 'pub const AMOUNT_BOUND: u64 = 0x0ccc_cccc_cccc_cccc;',
     'pub const AMOUNT_BOUND: u64 = 0x0ccc_cccc_cccc_cccd;', AMOUNT_TEST),
    ('caller_usd_check_gt', L, 'if request.initial_usd >= AMOUNT_BOUND {', 'if request.initial_usd > AMOUNT_BOUND {', AMOUNT_TEST),
    ('caller_fee_check_removed', L, 'if fee >= AMOUNT_BOUND {', 'if false && fee >= AMOUNT_BOUND {', AMOUNT_TEST),
    ('caller_reports_bound_not_value', L, 'CallerReject::AmountTooLarge { value: request.initial_usd }',
     'CallerReject::AmountTooLarge { value: AMOUNT_BOUND }', CORPUS_TEST),
    ('keccak_sha3_delimiter', K, 'const DELIMITER: u8 = 0x01;', 'const DELIMITER: u8 = 0x06;', KECCAK_TEST),
    ('keccak_rate_168', K, 'const RATE: usize = 136;', 'const RATE: usize = 168;', KECCAK_TEST),
    ('keccak_pad_bit', K, 'self.buffer[RATE - 1] ^= 0x80;', 'self.buffer[RATE - 1] ^= 0x40;', KECCAK_TEST),
    # the published vectors are shorter than one block and the chunking test compares the code with itself:
    # only the corpus (preimages past 136 bytes) catches a skipped block permutation
    ('keccak_skip_block_permute', K, '                permute_bytes(&mut self.buffer);\n                self.offset = 0;',
     '                self.offset = 0;', CORPUS_TEST),
    ('keccak_overwrite_not_xor', K, '*byte ^= new;', '*byte = *new;', CORPUS_TEST),
    ('keccak_delimiter_at_zero', K, 'self.buffer[self.offset] ^= DELIMITER;', 'self.buffer[0] ^= DELIMITER;', KECCAK_TEST),
    ('keccak_output_window', K, 'out.copy_from_slice(&self.buffer[..32]);', 'out.copy_from_slice(&self.buffer[8..40]);', KECCAK_TEST),
]
# controls only used by --selftest
SURVIVOR = ('equivalent_edit', K, 'input.len().min(RATE - self.offset)', 'input.len().min(RATE - self.offset + 0)', CORPUS_TEST)
BROKEN = ('does_not_compile', K, 'const RATE: usize = 136;', 'const RATE: usize = "136";', CORPUS_TEST)
# one flipped bit (0 -> 1 in the last hex digit) in the frozen corpus must fail the corpus test
ANCHOR_DIGEST = '91378d2649be144c8abfa4d4b7626d5413ceb45ee2038e0a306c1e6cdd4c676c'
ANCHOR_PREIMAGE = '92d92a' + (b'0x' + b'0' * 40).hex() + '84a46e616d65a176ab6465736372697074696f6ea0aa696e697469616c55736401a56e6f6e636502'
# (the anchor's preimage and digest also occur in the corpus rows that only differ in maxUsdcFee, so the edit
# text includes the start of the anchor row to stay unique)
ANCHOR_ROW = ('anchor-000\tanchor\t' + '00' * 20 + '\thex:76\thex:\t1\t2\t-\tok\t85\t'
              '6624f452420188a2c925ed1c5fee0e1042ed0f60c4de91f35ab2e5c319b2018b\t')
CORPUS_BIT_FLIPS = [
    ('corpus_digest_bit', '@corpus.tsv', ANCHOR_ROW + ANCHOR_PREIMAGE + '\t' + ANCHOR_DIGEST,
     ANCHOR_ROW + ANCHOR_PREIMAGE + '\t' + ANCHOR_DIGEST[:-1] + 'd', CORPUS_TEST),
    ('corpus_preimage_bit', '@corpus.tsv', ANCHOR_ROW + ANCHOR_PREIMAGE, ANCHOR_ROW + ANCHOR_PREIMAGE[:-1] + '3', CORPUS_TEST),
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


def sh(cmd, cwd, timeout=600):
    try:
        run = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvError('cannot run %s: %s' % (cmd[0], exc))
    return run.returncode, run.stdout + run.stderr


def prepare_base(out):
    base = os.path.join(out, 'base')
    shutil.copytree(CRATE, os.path.join(base, 'src', 'node115-vault-address'), ignore=shutil.ignore_patterns('target'))
    os.makedirs(os.path.join(base, 'src', 'node115-sponge-permutation'))
    shutil.copy(os.path.join(ROOT, 'src', 'node115-sponge-permutation', 'lib.rs'),
                os.path.join(base, 'src', 'node115-sponge-permutation', 'lib.rs'))
    os.makedirs(os.path.join(base, PACKET_REL))
    for name in ('corpus.tsv', 'wrong-variants.tsv', 'pins.json'):
        shutil.copy(os.path.join(HERE, name), os.path.join(base, PACKET_REL, name))
    return base


def cargo(cargo_bin, tree, target, extra):
    manifest = os.path.join(tree, 'src', 'node115-vault-address', 'Cargo.toml')
    return [cargo_bin, 'test', '--offline', '--locked', '--manifest-path', manifest, '--target-dir', target] + extra


def evaluate(base, mutant, cargo_bin, work):
    """Returns (status, failed tests). Raises EnvError for anything that is not a test verdict."""
    mid, rel, old, new, expect = mutant
    tree = os.path.join(work, mid)
    shutil.copytree(base, tree)
    # a leading '@' names a file of the packet copy (corpus corruption controls) instead of a crate file
    path = os.path.join(tree, PACKET_REL, rel[1:]) if rel.startswith('@') else os.path.join(tree, 'src', 'node115-vault-address', rel)
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
            print('%-34s %s' % (m[0], status))
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
