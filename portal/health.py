"""Independent task checkpoints; the Docker probe does not depend on the web server."""
import json
import os
from pathlib import Path
import sys
import threading
import time
from storage import atomic_write, read_json

TASKS = {'background': 300, 'watchdog': 180, 'heartbeat': 180, 'backup': 900,
         'geo': 1200, 'apps': 3900, 'routing-audit': 900}


def directory():
    return Path(os.environ.get('GEOVPN_DATA', '/data')) / 'health'


def checkpoint(name, success, error=None):
    path = directory() / (name + '.json')
    previous = read_json(path, {})
    now = time.time()
    state = {'checked': now, 'started': previous.get('started', now),
             'last_success': now if success else previous.get('last_success', 0),
             'ok': success, 'error': error}
    atomic_write(path, json.dumps(state))


def failures(now=None):
    now = time.time() if now is None else now
    result = []
    for name, limit in TASKS.items():
        try: state = read_json(directory() / (name + '.json'), {})
        except (OSError, ValueError): state = {}
        if not state or now - state.get('checked', 0) > limit or not state.get('ok'):
            result.append(name)
    return result


def start(name, function, interval):
    checkpoint(name, True)
    def worker():
        while True:
            try:
                function()
                checkpoint(name, True)
            except Exception as error:
                # Checkpoint errors must not terminate the supervising loop either.
                try: checkpoint(name, False, type(error).__name__)
                except Exception: pass
                print('task failed:', name, type(error).__name__, flush=True)
            time.sleep(interval)
    thread = threading.Thread(target=worker, name=name, daemon=True)
    thread.start()
    return thread


if __name__ == '__main__':
    bad = failures()
    print('unhealthy: ' + ', '.join(bad) if bad else 'healthy')
    sys.exit(bool(bad))
