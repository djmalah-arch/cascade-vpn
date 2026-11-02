"""Literal, atomic env-file updates; values are data, never sed expressions."""
from pathlib import Path
import re
import sys
from storage import atomic_write


def set_values(path, values):
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\n" in value or "\r" in value:
            raise ValueError("Environment keys/values must be single-line literals")
    p = Path(path)
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    lines = [line for line in lines if line.split("=", 1)[0] not in values]
    atomic_write(p, "\n".join(lines + [f"{k}={v}" for k, v in values.items()]) + "\n")


if __name__ == "__main__":
    set_values(sys.argv[1], {sys.argv[2]: sys.argv[3]})
