"""Bounded login attempts per trusted client IP and across the installation."""
import threading
import time
from collections import OrderedDict


class LoginLimits:
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock, self.attempts = clock, threading.Lock(), OrderedDict()

    def allowed(self, address):
        with self.lock:
            now = self.clock()
            for key in (address, '*'):
                rows = [t for t in self.attempts.get(key, []) if now - t < 600]
                if len(rows) >= (100 if key == '*' else 5): return False
            for key in (address, '*'):
                self.attempts[key] = [t for t in self.attempts.get(key, []) if now - t < 600] + [now]
                self.attempts.move_to_end(key)
            if len(self.attempts) > 10000:
                self.attempts.popitem(last=False)
            return True
