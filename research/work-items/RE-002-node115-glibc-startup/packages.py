"""Read startup objects from the signed Ubuntu base-release package indexes."""
import hashlib
import io
import lzma
import re
import subprocess
import tarfile
import urllib.request

BASE = 'https://archive.ubuntu.com/ubuntu/'
INDEX = 'main/binary-amd64/Packages.xz'
RELEASES = {'focal': 'cc9be89a0984aeca9e3ca40ae0e6decff75aa32653a5925b04956a7c12487e99',
            'noble': 'cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0'}
SIGNER = 'F6ECB3762474EDA9D21B7022871920D1991BC93C'
NAMES = ('Scrt1.o', 'crt1.o', 'rcrt1.o')


def require(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def resource(path, url_path, expected, fetch):
    if not path.is_file() and fetch:
        with urllib.request.urlopen(BASE + url_path, timeout=60) as response:
            data = response.read()
        require(sha(data) == expected, f'Download checksum mismatch: {url_path}')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    data = path.read_bytes()
    require(sha(data) == expected, f'Checksum mismatch: {path.name}')
    return data


def ubuntu(cache, suite, keyring, fetch, package='libc6-dev'):
    require(package in ('libc6-dev', 'libc6'), 'Unsupported package')
    directory = cache / suite
    prefix = 'dists/' + suite + '/'
    release = resource(directory / 'InRelease', prefix + 'InRelease', RELEASES[suite], fetch)
    status = subprocess.check_output(['gpgv', '--keyring', str(keyring.resolve()), '--status-fd', '1',
                                      str(directory / 'InRelease')]).decode()
    signers = sorted(re.findall(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ', status, re.M))
    require(SIGNER in signers, 'Expected Ubuntu archive 2018 signing key')
    checksums = re.search(rb'^SHA256:\n((?: [^\n]+\n)+)', release, re.M)
    require(checksums, 'Signed SHA256 stanza missing')
    (index_hash, size, _), = (line.split() for line in checksums[1].decode().splitlines()
                               if line.split()[-1] == INDEX)
    index = resource(directory / 'Packages.xz', prefix + INDEX, index_hash, fetch)
    require(len(index) == int(size), 'Signed index size mismatch')
    stanzas = lzma.decompress(index).decode().split('\n\n')
    stanza, = (s for s in stanzas if s.startswith(f'Package: {package}\n'))
    fields = dict(line.split(': ', 1) for line in stanza.splitlines()
                  if not line.startswith(' ') and ': ' in line)
    require(fields['Architecture'] == 'amd64' and fields['Source'] == 'glibc', 'Wrong base package')
    filename = fields['Filename']
    require(re.fullmatch(rf'pool/main/g/glibc/{package}_[\w.+~-]+_amd64\.deb', filename), 'Wrong package path')
    deb = directory / (package + '.deb')
    data = resource(deb, filename, fields['SHA256'], fetch)
    require(len(data) == int(fields['Size']), 'Signed package size mismatch')
    archive, = (a for a in subprocess.check_output(['ar', 't', str(deb)]).decode().splitlines()
                if a in ('data.tar.xz', 'data.tar.zst'))
    compressed = subprocess.check_output(['ar', 'p', str(deb), archive])
    raw = lzma.decompress(compressed) if archive.endswith('xz') else subprocess.check_output(
        ['zstd', '-qdc'], input=compressed)
    objects = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for name in (NAMES if package == 'libc6-dev' else ('libc.so.6',)):
            member = tar.getmember('./usr/lib/x86_64-linux-gnu/' + name)
            require(member.isfile(), 'Expected regular startup object')
            with tar.extractfile(member) as stream:
                objects[name] = stream.read()
    proof = dict(suite=suite, release_sha256=RELEASES[suite], signers=signers, index_sha256=index_hash,
                 package=filename, version=fields['Version'], package_sha256=fields['SHA256'], package_bytes=len(data))
    return proof, objects
