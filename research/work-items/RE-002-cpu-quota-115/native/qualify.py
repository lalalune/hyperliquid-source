#!/usr/bin/env python3
"""Qualify only the independent Rust projection; checks remain active with -O."""
from pathlib import Path
import subprocess, json, hashlib, time, argparse
parser = argparse.ArgumentParser(description='Compile and qualify only the independently authored CPU projection.')
parser.add_argument('--rustc', type=Path, action='append', required=True)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[4]
packet = root / 'research/work-items/RE-002-cpu-quota-115'
work = args.out.resolve()
work.mkdir(parents=True, exist_ok=True)
if not not work.is_relative_to(packet):
    raise ValueError('Outputs must be outside the evidence packet')
source = root / 'src/node115-cpu-quota/src/lib.rs'
driver = packet / 'native/driver.rs'
lines = []
expected = []
qrows = json.loads((packet / 'oracle/vectors.json').read_text())
arows = json.loads((packet / 'oracle/affinity-vectors.json').read_text())
for i, r in enumerate(qrows):
    initial = [0, 17, (1 << 64) - 1][i % 3]
    lines.append(f"Q {r['quota']} {r['period']} {r['logical']} {initial}")
    vals = [r[x] for x in ('quota_bits', 'period_bits', 'ratio_bits', 'rounded_quota', 'store')]
    vals.append(initial if r['store'] is None else r['store'])
    expected.append(' '.join(('-' if x is None else str(x) for x in vals)))
for r in arows:
    m = ' '.join((f'{x:016x}' for x in r['mask'])) if r['mask'] is not None else '-'
    lines.append(f"A {r['sysconf']} {r['cache']} {m}")
    expected.append(f"{r['logical']} {r['cached_or_logical']}")
input_bytes = ('\n'.join(lines) + '\n').encode()
expect_bytes = ('\n'.join(expected) + '\n').encode()
(work / 'inputs.txt').write_bytes(input_bytes)
(work / 'expected.txt').write_bytes(expect_bytes)
commands = []
builds = []
controls = []

def sha(x):
    return hashlib.sha256(x).hexdigest()

def run(args, label, inp=None):
    r = subprocess.run([str(x) for x in args], input=inp, capture_output=True)
    (work / (label + '.stdout')).write_bytes(r.stdout)
    (work / (label + '.stderr')).write_bytes(r.stderr)
    commands.append(dict(label=label, argv=[str(x).replace(str(root), '<repo>').replace(str(Path.home()), '<user>') for x in args], exit_code=r.returncode, stdout_sha256=sha(r.stdout), stderr_sha256=sha(r.stderr)))
    if not r.returncode == 0:
        raise ValueError((label, r.stderr.decode()))
    return r.stdout

def build(src, compiler, opt, label):
    out = work / label
    out.mkdir(exist_ok=True)
    lib = out / 'libnode115_cpu_quota.rlib'
    exe = out / 'driver'
    run([compiler, '--edition=2024', '--crate-name', 'node115_cpu_quota', '--crate-type', 'rlib', '-C', 'opt-level=' + str(opt), src, '-o', lib], label + '-lib')
    run([compiler, '--edition=2024', '-C', 'opt-level=' + str(opt), driver, '--extern', 'node115_cpu_quota=' + str(lib), '-o', exe], label + '-driver')
    return (exe, lib)
for ordinal, compiler in enumerate(args.rustc):
    tool = run([compiler, '-Vv'], f'compiler{ordinal}-version').decode()
    version = f'compiler{ordinal}-' + tool.splitlines()[0].split()[1]
    for opt in (0, 3):
        label = f'{version}-opt{opt}'
        exe, lib = build(source, compiler, opt, label)
        out = run([exe], label + '-run', input_bytes)
        if not out == expect_bytes:
            raise ValueError(label)
        builds.append(dict(label=label, cases=len(lines), compiler=tool, rlib_sha256=sha(lib.read_bytes()), output_sha256=sha(out)))
        print('PASS', label, len(lines), flush=True)
text = source.read_text()
mutants = {'input_precision': ('let q = quota as f64;', 'let q = quota as f32 as f64;'), 'ceil_to_floor': ('rounded_quota: ratio.ceil() as u64,', 'rounded_quota: ratio.floor() as u64,'), 'integer_ceildiv': ('rounded_quota: ratio.ceil() as u64,', 'rounded_quota: ((quota as u128 + period as u128 - 1) / period as u128) as u64,'), 'minimum_to_maximum': ('quota.min(logical)', 'quota.max(logical)'), 'zero_publication': ('if quota == 0 {', 'if quota == u64::MAX {'), 'signed_fallback_zero': ('sysconf_result.max(1)', 'sysconf_result.max(0)'), 'affinity_first_word_only': ('words.iter().map(|w| u64::from(w.count_ones())).sum()', 'u64::from(words[0].count_ones())'), 'cache_precedence_inverted': ('if loaded_cache != 0 {', 'if loaded_cache == 0 {')}
for name, (old, new) in mutants.items():
    if not text.count(old) == 1:
        raise ValueError(name)
    mut = work / (name + '.rs')
    mut.write_text(text.replace(old, new))
    exe, lib = build(mut, compiler, 3, 'mutant-' + name)
    out = run([exe], 'mutant-' + name + '-run', input_bytes)
    actual = out.decode().splitlines()
    if not len(actual) == len(expected):
        raise ValueError('native qualification check failed')
    diff = [i for i, (a, e) in enumerate(zip(actual, expected)) if a != e]
    if not diff:
        raise ValueError(name)
    controls.append(dict(name=name, normal_return=True, differences=len(diff), first_index=diff[0], input=lines[diff[0]], expected=expected[diff[0]], actual=actual[diff[0]], source_sha256=sha(mut.read_bytes())))
    print('DETECTED', name, len(diff), flush=True)
result = dict(target_sha256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301', source_sha256=sha(source.read_bytes()), driver_sha256=sha(driver.read_bytes()), input_sha256=sha(input_bytes), expected_sha256=sha(expect_bytes), quota_cases=len(qrows), affinity_cases=len(arows), correct_builds=builds, compiled_mutant_controls=controls, captured_execution=False, concurrency_proven=False, source_byte_match_claimed=False)
(work / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
(work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
