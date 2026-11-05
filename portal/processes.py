"""Wait for children and terminate the whole command group on timeout."""
import os
import re
import signal
import subprocess


def clean_error(text):
    text = re.sub(r'https?://\S+', '[URL]', text)
    text = re.sub(r'(?i)((?:password|secret|token|privatekey)\s*[=:]\s*)\S+', r'\1[redacted]', text)
    return text[-2000:]


def run(command, timeout=20):
    process = subprocess.Popen(command, shell=isinstance(command, str), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True,
                               executable='/bin/bash' if isinstance(command, str) else None,
                               start_new_session=os.name != 'nt')
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == 'nt': process.kill()
        else:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        stdout, stderr = process.communicate()
        return 124, clean_error('Command timed out. ' + stderr + '\n' + stdout)
    if process.returncode:
        return process.returncode, clean_error(stderr + '\n' + stdout)
    return 0, stdout.strip()
