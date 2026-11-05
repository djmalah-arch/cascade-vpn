"""Bounded-memory downloads restricted to current personal-page capabilities."""
import os
from pathlib import Path
import re
import shutil
from storage import read_json
from mirror import digest

VERIFIED = {}


def send(handler, root, name, authorized):
    if not authorized or not re.fullmatch(r'[A-Za-z0-9_.+-]+', name): return handler.not_found()
    root = Path(root).resolve()
    path = (root / name).resolve()
    if path.parent != root or not path.is_file(): return handler.not_found()
    record = read_json(root / 'apps.json', {}).get('verified', {}).get(name)
    if not record: return handler.not_found()
    stat = path.stat()
    identity = (name, stat.st_ino, stat.st_mtime_ns, stat.st_size, record['sha256'])
    if identity not in VERIFIED:
        if stat.st_size != record['size'] or digest(path) != record['sha256']: return handler.not_found()
        if len(VERIFIED) > 64: VERIFIED.clear()
        VERIFIED[identity] = True
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/octet-stream')
    handler.send_header('Content-Length', str(stat.st_size))
    handler.send_header('Content-Disposition', 'attachment; filename="' + name + '"')
    handler.send_header('Cache-Control', 'private, no-store')
    handler.send_header('Referrer-Policy', 'no-referrer')
    handler.end_headers()
    with open(path, 'rb') as stream: shutil.copyfileobj(stream, handler.wfile, 65536)
