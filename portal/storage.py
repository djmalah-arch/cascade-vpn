"""Durable JSON files and a reentrant lock shared by portal and CLI processes."""
import json
import os
from pathlib import Path
import tempfile
import threading


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            os.chmod(tmp, mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        if default is not None: return default
        raise


class ProcessLock:
    """One lock order: thread RLock, then OS lock; nested calls reuse the OS lock."""
    def __init__(self, path):
        self.path = path
        self.thread = threading.RLock()
        self.depth = 0
        self.file = None

    def __enter__(self):
        self.thread.acquire()
        try:
            if self.depth == 0:
                path = self.path() if callable(self.path) else self.path
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                self.file = open(path, "a+b")
                if os.name == "nt":
                    import msvcrt
                    if os.path.getsize(path) == 0:
                        self.file.write(b"\0"); self.file.flush()
                    self.file.seek(0)
                    # LK_LOCK has a short retry limit; use bounded polling without a total timeout.
                    import time
                    while True:
                        try:
                            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
                            break
                        except OSError: time.sleep(0.05)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_EX)
            self.depth += 1
            return self
        except BaseException:
            if self.file: self.file.close(); self.file = None
            self.thread.release()
            raise

    def __exit__(self, *args):
        try:
            self.depth -= 1
            if self.depth == 0:
                if os.name == "nt":
                    import msvcrt
                    self.file.seek(0)
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
                self.file.close()
                self.file = None
        finally:
            self.thread.release()
