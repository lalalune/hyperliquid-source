"""Compare node115's libstdc++ requirements with exports from authenticated Ubuntu base releases."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
TARGET = HERE.parents[2] / 'artifacts/node/115/hl-node'
TARGET_HASH = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
INDEX = 'main/binary-amd64/Packages.xz'
ARCHIVE = 'https://archive.ubuntu.com/ubuntu/'
SIGNER = 'F6ECB3762474EDA9D21B7022871920D1991BC93C'
RELEASES = {
    'focal': 'cc9be89a0984aeca9e3ca40ae0e6decff75aa32653a5925b04956a7c12487e99',
    'noble': 'cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, check=True,
                          env=dict(os.environ, LC_ALL='C')).stdout


def resource(path, url, sha, fetch):
    if fetch and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        data = run(['curl', '-fsSL', '--retry', '2', url])
        require(digest(data) == sha, f'Download SHA-256 mismatch: {url}')
        path.write_bytes(data)
    data = path.read_bytes()
    require(digest(data) == sha, f'SHA-256 mismatch: {path.name}')
    return data


def package(suite, directory, keyring, fetch):
    base = ARCHIVE + 'dists/' + suite + '/'
    release = resource(directory / 'InRelease', base + 'InRelease', RELEASES[suite], fetch)
    signed = run(['gpgv', '--status-fd', '1', '--keyring', str(keyring),
                  str(directory / 'InRelease')]).decode()
    signers = sorted(re.findall(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ', signed, re.M))
    require(SIGNER in signers, 'Required Ubuntu archive signer missing')
    text = release.decode()
    sha_section = re.search(r'^SHA256:\n((?: [^\n]+\n)+)', text, re.M).group(1)
    matches = [line.split() for line in sha_section.splitlines() if line.split()[-1] == INDEX]
    (index_hash, index_size, _), = matches
    index = resource(directory / 'Packages.xz', base + INDEX, index_hash, fetch)
    require(len(index) == int(index_size), 'Index size mismatch')
    records = [r for r in lzma.decompress(index).decode().split('\n\n')
               if r.startswith('Package: libstdc++6\n')]
    record, = records
    fields = dict(line.split(': ', 1) for line in record.splitlines()
                  if line and not line.startswith(' ') and ': ' in line)
    require(fields['Architecture'] == 'amd64', 'Wrong package architecture')
    deb = directory / 'provider.deb'
    deb_data = resource(deb, ARCHIVE + fields['Filename'], fields['SHA256'], fetch)
    require(len(deb_data) == int(fields['Size']), 'Package size mismatch')
    archive, = [a for a in run(['ar', 't', str(deb)]).decode().splitlines()
                if a in ('data.tar.xz', 'data.tar.zst')]
    packed = run(['ar', 'p', str(deb), archive])
    raw = lzma.decompress(packed) if archive.endswith('xz') else run(['zstd', '-qdc'], packed)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        soname = tar.getmember('./usr/lib/x86_64-linux-gnu/libstdc++.so.6')
        require(soname.issym() and re.fullmatch(r'libstdc\+\+\.so\.6\.0\.\d+', soname.linkname),
                'Unexpected SONAME symlink')
        member = tar.getmember('./usr/lib/x86_64-linux-gnu/' + soname.linkname)
        require(member.isfile(), 'Expected a regular DSO member')
        body = tar.extractfile(member).read()
    provenance = dict(suite=suite, signers=signers, release_sha256=RELEASES[suite],
                      index_sha256=index_hash, version=fields['Version'], deb_path=fields['Filename'],
                      deb_sha256=fields['SHA256'], deb_bytes=len(deb_data), dso_member=member.name,
                      dso_sha256=digest(body), dso_bytes=len(body))
    return provenance, body


def symbols(readelf, image):
    output = run([readelf, '-W', '--dyn-syms', str(image)]).decode()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(':') or not fields[0][:-1].isdigit():
            continue
        _, _, _, typ, binding, visibility, section, qualified, *rest = fields
        yield typ, binding, visibility, section, qualified, rest


def requirements(readelf, target):
    require(digest(target.read_bytes()) == TARGET_HASH, 'Wrong node #115')
    versions = run([readelf, '-WV', str(target)]).decode()
    owners = {}
    owner = None
    for line in versions.splitlines():
        file = re.search(r'\bFile: (\S+)\s+Cnt:', line)
        version = re.search(r'\bName: (\S+)\s+Flags: .*?\s+Version: (\d+)', line)
        if file:
            owner = file[1]
        elif version:
            owners[version[2]] = (owner, version[1])
    imports = []
    for typ, binding, visibility, section, name, suffix in symbols(readelf, target):
        if section != 'UND' or not suffix or '@' not in name:
            continue
        owner, version = owners[suffix[0].strip('()')]
        if owner == 'libstdc++.so.6':
            symbol, shown = name.split('@')
            require(shown == version and binding in ('GLOBAL', 'WEAK'), 'Bad required import')
            imports.append(dict(symbol=symbol, version=version, type=typ, binding=binding))
    require(len(imports) == 165, 'Incomplete target requirements')
    return imports


def exports(readelf, image):
    dynamic = run([readelf, '-Wd', str(image)]).decode()
    require(re.search(r'\(SONAME\).*\[libstdc\+\+\.so\.6\]', dynamic), 'Wrong provider SONAME')
    result = {}
    for typ, binding, visibility, section, qualified, _ in symbols(readelf, image):
        if section == 'UND' or binding not in ('GLOBAL', 'WEAK', 'UNIQUE') or visibility not in ('DEFAULT','PROTECTED'):
            continue
        if '@' in qualified:
            name, version = qualified.split('@', 1)
            result.setdefault(name, []).append((version.lstrip('@'), typ))
    return result


def evaluate(imports, providers):
    rows = []
    for required in imports:
        row = dict(required)
        for suite, symbols_by_name in providers.items():
            offered = symbols_by_name.get(required['symbol'], [])
            row[suite] = dict(match=(required['version'], required['type']) in offered,
                              available=sorted({v for v,t in offered if t == required['type']}))
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cache', type=Path)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--readelf', default='readelf')
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--print-result', action='store_true')
    args = parser.parse_args()
    imports = requirements(args.readelf, TARGET)
    providers, records = {}, []
    with tempfile.TemporaryDirectory() as temp:
        for suite in RELEASES:
            meta, data = package(suite, args.cache / suite, args.keyring.resolve(), args.fetch)
            image = Path(temp) / suite
            image.write_bytes(data)
            providers[suite] = exports(args.readelf, image)
            records.append(meta)
    rows = evaluate(imports, providers)
    receipt = dict(target_sha256=TARGET_HASH, packages=records, imports=rows)
    if args.print_result:
        print(json.dumps(receipt, indent=2))
    else:
        require(receipt == json.loads((HERE / 'result.json').read_text()), 'Receipt mismatch')
        for suite in RELEASES:
            for binding in ('GLOBAL', 'WEAK'):
                selected = [r[suite]['match'] for r in rows if r['binding'] == binding]
                print(f'{suite}: {sum(selected)}/{len(selected)} {binding} imports match')


if __name__ == '__main__':
    main()
