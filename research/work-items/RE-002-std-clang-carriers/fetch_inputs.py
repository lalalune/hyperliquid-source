"""Fetch and verify the two pinned Rust data archives; never install or run them."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fetch(url, destination, maximum):
    parsed = urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname != 'static.rust-lang.org':
        raise ValueError('unexpected input authority')
    command = ['curl', '--disable', '--fail', '--silent', '--show-error',
               '--proto', '=https', '--proto-redir', '=https', '--location',
               '--max-time', '120', '--max-filesize', str(maximum),
               '--output', str(destination), '--write-out', '%{url_effective}\n%{http_code}\n', url]
    result = subprocess.run(command, capture_output=True, text=True, timeout=125)
    (destination.with_name(destination.name + '.curl.stdout')).write_text(result.stdout)
    (destination.with_name(destination.name + '.curl.stderr')).write_text(result.stderr)
    if result.returncode:
        raise RuntimeError('input download failed; preserve the partial output for inspection')
    effective, status = result.stdout.splitlines()
    if urlparse(effective).hostname != 'static.rust-lang.org' or status != '200':
        raise RuntimeError('unexpected final download authority/status')


def verify(gpg, keyring, path, fingerprint):
    command = [gpg, '--no-options', '--homedir', str(keyring), '--batch',
               '--no-auto-key-retrieve', '--status-fd', '1',
               '--verify', str(path) + '.asc', str(path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    path.with_name(path.name + '.gpg-status').write_text(result.stdout)
    path.with_name(path.name + '.gpg-stderr').write_text(result.stderr)
    if result.returncode or not any(
            line.startswith('[GNUPG:] VALIDSIG ' + fingerprint + ' ')
            for line in result.stdout.splitlines()):
        raise RuntimeError('signature failed: ' + path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='fresh owned directory')
    parser.add_argument('--gpg', default=shutil.which('gpg'))
    args = parser.parse_args()
    if not args.gpg:
        parser.error('GnuPG is required; no tool is installed by this script')
    data = json.loads((HERE / 'inputs.json').read_text())
    if len(data['archives']) != 2 or {row['version'] for row in data['archives']} != {'1.94.1', '1.95.0'}:
        raise ValueError('this probe accepts only the two declared releases')
    key = HERE / 'authentication/rust-release-key.asc'
    if sha(key) != data['release_key']['sha256']:
        raise ValueError('retained public key hash differs')
    args.out.mkdir(parents=True, exist_ok=False)
    # A short owned directory avoids Unix-domain socket limits in long worktrees.
    with tempfile.TemporaryDirectory(prefix='re002-gpg-') as temporary:
        keyring = Path(temporary)
        result = subprocess.run([args.gpg, '--no-options', '--homedir', str(keyring),
                                 '--batch', '--no-auto-key-retrieve', '--import', str(key)],
                                capture_output=True, text=True, timeout=30)
        (args.out / 'key-import.stdout').write_text(result.stdout)
        (args.out / 'key-import.stderr').write_text(result.stderr)
        if result.returncode:
            raise RuntimeError('retained public key import failed')
        records = []
        for row in data['archives']:
            if Path(row['filename']).name != row['filename']:
                raise ValueError('non-basename input filename')
            manifest = args.out / ('channel-rust-' + row['version'] + '.toml')
            fetch(row['manifest_url'], manifest, 2000000)
            if sha(manifest) != row['manifest_sha256']:
                raise ValueError('official manifest hash differs')
            fetch(row['manifest_signature_url'], manifest.with_name(manifest.name + '.asc'), 20000)
            verify(args.gpg, keyring, manifest, row['signing_fingerprint'])
            archive = args.out / row['filename']
            fetch(row['url'], archive, 40000000)
            if archive.stat().st_size != row['bytes'] or sha(archive) != row['sha256']:
                raise ValueError('official archive size/hash differs')
            fetch(row['archive_signature_url'], archive.with_name(archive.name + '.asc'), 20000)
            verify(args.gpg, keyring, archive, row['signing_fingerprint'])
            archive.chmod(0o444)
            records.append({'version': row['version'], 'bytes': row['bytes'],
                            'sha256': row['sha256'], 'signature_fingerprint': row['signing_fingerprint'],
                            'installed_or_executed': False})
            (args.out / 'authentication.json').write_text(json.dumps(records, indent=2) + '\n')
            print(json.dumps(records[-1]), flush=True)


if __name__ == '__main__':
    main()
