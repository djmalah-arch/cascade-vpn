"""Publish installer bytes only after matching the digest in the official GitHub release."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from storage import atomic_write, read_json
from processes import run

RELEASES = {
    'amnezia-vpn/amnezia-client': {
        'AmneziaVPN-windows.exe': r'_windows_x64\.exe$', 'AmneziaVPN-android.apk': r'android11\+_arm64-v8a\.apk$',
        'AmneziaVPN-android-9-10.apk': r'android9-10_arm64-v8a\.apk$', 'AmneziaVPN-macos.pkg': r'_macos_x64\.pkg$'},
    'hiddify/hiddify-app': {'Hiddify-windows.exe': r'Windows-Setup-x64\.exe$',
        'Hiddify-android.apk': r'Android-universal\.apk$', 'Hiddify-macos.dmg': r'MacOS\.dmg$'},
    'Happ-proxy/happ-desktop': {'Happ-windows.exe': r'^setup-Happ\.x64\.exe$', 'Happ-macos.dmg': r'macOS\.universal\.dmg$'},
    'Happ-proxy/happ-android': {'Happ-android.apk': r'^Happ\.apk$'},
    'telegramdesktop/tdesktop': {'Telegram-windows.exe': r'^td-setup-win-x64-[0-9.]+\.exe$',
        'Telegram-macos.dmg': r'^td-setup-mac-[0-9.]+\.dmg$'},
}


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): value.update(block)
    return value.hexdigest()


def expected_digest(asset):
    value = asset.get('digest', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('Official release has no SHA-256 digest; installer withheld')
    if not asset.get('browser_download_url', '').startswith('https://github.com/'):
        raise ValueError('Unexpected installer source')
    return value[7:]


def publish(root, name, asset, version):
    expected = expected_digest(asset)
    target = root / name
    if not target.is_file() or digest(target) != expected:
        fd, temporary = tempfile.mkstemp(prefix='.installer-', dir=root)
        os.close(fd)
        try:
            rc, error = run(['curl', '-fLsS', '--connect-timeout', '10', '--max-time', '900',
                             '--retry', '2', '--retry-max-time', '1200', '-o', temporary,
                             asset['browser_download_url']], timeout=1250)
            if rc: raise RuntimeError('Installer download failed: ' + error)
            if digest(temporary) != expected: raise ValueError('Installer SHA-256 mismatch')
            os.chmod(temporary, 0o644)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    return {'sha256': expected, 'size': target.stat().st_size, 'version': version,
            'source': asset['browser_download_url'], 'verification': 'official-github-release-digest'}


def update(root):
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    old = read_json(root / 'apps.json', {})
    verified = dict(old.get('verified', {}))
    errors = []
    for repo, files in RELEASES.items():
        rc, body = run(['curl', '-fLsS', '--connect-timeout', '10', '--max-time', '60',
                        'https://api.github.com/repos/' + repo + '/releases/latest'], timeout=65)
        if rc:
            errors.append(repo + ': release metadata unavailable: ' + body); continue
        try: release = json.loads(body)
        except ValueError:
            errors.append(repo + ': invalid release metadata'); continue
        for name, pattern in files.items():
            try:
                asset = next(a for a in release.get('assets', []) if re.search(pattern, a['name']))
                verified[name] = publish(root, name, asset, release['tag_name'])
            except (StopIteration, ValueError, RuntimeError) as error:
                errors.append(name + ': ' + (str(error) or 'asset missing'))
    # Existing verified versions survive upstream failures; legacy unverified files are never advertised.
    verified = {n: v for n, v in verified.items() if (root / n).is_file() and digest(root / n) == v['sha256']}
    atomic_write(root / 'apps.json', json.dumps({'verified': verified,
        'sizes': {n: v['size'] for n, v in verified.items()},
        'file_versions': {n: v['version'] for n, v in verified.items()}, 'versions': old.get('versions', {})}), mode=0o644)
    if errors: raise RuntimeError('; '.join(errors))


if __name__ == '__main__':
    from storage import ProcessLock
    root = os.environ.get('APP_DIR', '/opt/geovpn-portal/app')
    with ProcessLock(str(Path(root) / '.update.lock')): update(root)
