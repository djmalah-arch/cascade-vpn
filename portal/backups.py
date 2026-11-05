"""Versioned, portable backup format; restoration never overwrites an installation."""
import datetime as dt
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import subprocess

REQUIRED = ("install.env", "remnawave.env", "Caddyfile", "portal/db.json", "portal/state.json")
BACKUP_NAME_RE = r"^msk-[0-9]{8}-[0-9]{4}([0-9]{2}-[0-9]{6})?\.tar\.gz(\.enc)?$"
EXCLUDED = ("portal/backups", "apps", "public", "public-run", "restore.dump", "restore.dump.applied")


def create(data, dump, destination, provenance=None):
    data, destination = Path(data), Path(destination)
    for name in REQUIRED:
        if not (data / name).is_file(): raise ValueError(f"Backup source missing: {name}")
    with open(dump, "rb") as f:
        if f.read(5) != b"PGDMP": raise ValueError("Invalid PostgreSQL custom dump")
    fd, tmp = tempfile.mkstemp(dir=destination.parent, prefix=".backup-", suffix=".part")
    os.close(fd)
    try:
        os.chmod(tmp, 0o600)
        with tarfile.open(tmp, "w:gz") as tf:
            manifest = json.dumps({"version": 2, "created": dt.datetime.now(dt.timezone.utc).isoformat(),
                                   "provenance": provenance or {}}).encode()
            info = tarfile.TarInfo("manifest.json"); info.size = len(manifest); info.mode = 0o600
            tf.addfile(info, io.BytesIO(manifest))
            tf.add(dump, arcname="database.dump")
            def include(info):
                relative = info.name.removeprefix("data/")
                if any(relative == p or relative.startswith(p + "/") for p in EXCLUDED): return None
                if info.issym() or info.islnk() or not (info.isdir() or info.isfile()):
                    raise ValueError(f"Unsupported backup entry: {info.name}")
                if relative.endswith((".lock", ".tmp", ".part")): return None
                return info
            tf.add(data, arcname="data", filter=include)
        with open(tmp, "r+b") as f: os.fsync(f.fileno())
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def encrypt(source, certificate, destination=None):
    """CMS authenticated encryption; the recovery private key is never needed on the VPN host."""
    source = Path(source)
    destination = Path(destination or (str(source) + '.enc'))
    fd, tmp = tempfile.mkstemp(dir=destination.parent, prefix='.encrypted-', suffix='.part')
    os.close(fd)
    try:
        result = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm',
            '-in', str(source), '-out', tmp, '-outform', 'DER', str(certificate)],
            capture_output=True, timeout=120)
        if result.returncode: raise RuntimeError('Backup encryption failed; archive not sent')
        os.chmod(tmp, 0o600)
        with open(tmp, 'rb') as stream: os.fsync(stream.fileno())
        os.replace(tmp, destination)
        return str(destination)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def decrypt(source, private_key, destination):
    result = subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
        '-in', str(source), '-inkey', str(private_key), '-out', str(destination)],
        capture_output=True, timeout=120)
    if result.returncode:
        Path(destination).unlink(missing_ok=True)
        raise ValueError('Backup authentication/decryption failed')
    os.chmod(destination, 0o600)


def restore(archive, target):
    target = Path(target).resolve()
    if target.exists(): raise ValueError("Restore target must not exist; use a fresh data directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".restore-") as tmp:
        staging = Path(tmp)
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            seen = set()
            for info in members:
                name = PurePosixPath(info.name)
                if (name.is_absolute() or ".." in name.parts or "\\" in info.name or ":" in info.name
                        or info.name in seen or info.issym() or info.islnk()
                        or not (info.isdir() or info.isfile())
                        or (name.parts[0] != "data" and info.name not in ("manifest.json", "database.dump"))):
                    raise ValueError(f"Unsafe archive member: {info.name}")
                seen.add(info.name)
            # Explicit extraction, compatible with Python 3.10+ and independent of tarfile defaults.
            for info in members:
                out = staging.joinpath(*PurePosixPath(info.name).parts)
                if info.isdir(): out.mkdir(parents=True, exist_ok=True)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with tf.extractfile(info) as src, open(out, "wb") as dst: shutil.copyfileobj(src, dst)
                    os.chmod(out, 0o600)
            with open(staging / "manifest.json") as f: manifest = json.load(f)
            if manifest.get("version") != 2: raise ValueError("Unsupported backup format")
            for name in REQUIRED:
                if not (staging / "data" / name).is_file(): raise ValueError(f"Incomplete backup: {name}")
            with open(staging / "database.dump", "rb") as f:
                if f.read(5) != b"PGDMP": raise ValueError("Invalid database dump")
        os.replace(staging / "database.dump", staging / "data" / "restore.dump")
        os.replace(staging / "data", target)
        os.chmod(target, 0o700)
