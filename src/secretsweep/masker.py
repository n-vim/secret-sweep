from __future__ import annotations

import hashlib


def mask_secret(value: str, visible: int = 4) -> str:
    """Return a safe display version of a secret-like value."""
    value = value.strip()
    if not value:
        return ""
    if len(value) <= visible * 2 + 3:
        return "*" * min(len(value), 12)
    left = value[:visible]
    right = value[-visible:]
    hidden = "*" * min(max(len(value) - visible * 2, 6), 24)
    return f"{left}{hidden}{right}"


def fingerprint(value: str) -> str:
    """Create a stable non-reversible fingerprint for grouping findings."""
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return digest[:16]


def mask_line(line: str, secret: str, masked: str) -> str:
    if not secret:
        return line.strip()
    return line.replace(secret, masked).strip()
