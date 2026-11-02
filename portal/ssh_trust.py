"""Persistent SSH host trust; password enrollment is explicit, automation rejects unknown keys."""
import base64
import hashlib
from pathlib import Path
import paramiko
from storage import ProcessLock, atomic_write


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def connect(host, port, trust_file, *, password=None, key_filename=None, expected=None, timeout=15):
    trust_file = Path(trust_file)
    client = paramiko.SSHClient()
    class Enroll(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, c, hostname, key):
            if expected and fingerprint(key) != expected:
                raise paramiko.SSHException("SSH fingerprint does not match the enrolled exit")
            if password is None and expected is None:
                raise paramiko.SSHException("Unknown SSH host key; enroll with geovpn host-extras first")
            c.get_host_keys().add(hostname, key.get_name(), key)
    try:
        with ProcessLock(str(trust_file) + ".lock"):
            if trust_file.exists(): client.load_host_keys(str(trust_file))
            client.set_missing_host_key_policy(Enroll())
            client.connect(host, port=port, username="root", password=password, key_filename=key_filename,
                           timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
                           allow_agent=False, look_for_keys=False)
            actual = client.get_transport().get_remote_server_key()
            if expected and fingerprint(actual) != expected:
                raise paramiko.SSHException("SSH fingerprint does not match the enrolled exit")
            # Persist only after successful authentication. Changed known keys are rejected by Paramiko.
            lines = [f"{name} {key.get_name()} {key.get_base64()}\n"
                     for name, keys in client.get_host_keys().items() for key in keys.values()]
            atomic_write(trust_file, "".join(lines))
        return client
    except BaseException:
        client.close()
        raise
