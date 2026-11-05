#!/usr/bin/env python3
"""Unpack a v2 backup on a fresh server; install.sh restores PostgreSQL before starting the panel."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "portal"))
from backups import restore, decrypt
import tempfile

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument('--key', help='Recovery private key for an encrypted .enc backup')
    parser.add_argument("--target", default=str(Path(__file__).resolve().parent / "data"))
    args = parser.parse_args()
    if args.archive.endswith('.enc'):
        if not args.key: parser.error('--key is required for an encrypted backup')
        with tempfile.TemporaryDirectory(prefix='geovpn-restore-') as directory:
            archive = Path(directory) / 'backup.tar.gz'
            decrypt(args.archive, args.key, archive)
            restore(archive, args.target)
    else:
        restore(args.archive, args.target)
    print("Backup unpacked. Update DNS to the new VPS, then run ./install.sh to restore and verify services.")
