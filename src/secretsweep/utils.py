from __future__ import annotations

from pathlib import Path
from typing import Iterable


def normalize_path(path: Path) -> str:
    return path.as_posix()


def relative_to_root(path: Path, root: Path) -> str:
    try:
        return normalize_path(path.relative_to(root))
    except ValueError:
        return normalize_path(path)


def is_binary_file(path: Path, sample_size: int = 4096) -> bool:
    try:
        chunk = path.read_bytes()[:sample_size]
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b"
    non_text = sum(1 for byte in chunk if byte not in text_chars)
    return non_text / max(len(chunk), 1) > 0.30


def is_ignored(path: Path, root: Path, ignore_names: Iterable[str]) -> bool:
    names = set(ignore_names)
    rel_parts = path.relative_to(root).parts if path != root else ()
    for part in rel_parts:
        if part in names:
            return True
    rel = relative_to_root(path, root)
    return rel in names


def should_scan_file(path: Path, extensions: set[str]) -> bool:
    if path.name in {"Dockerfile", "Makefile", ".env", ".env.local", ".env.production"}:
        return True
    if path.suffix in extensions:
        return True
    if ".env" in path.name:
        return True
    return False


def iter_project_files(root: Path, ignore_paths: list[str]) -> Iterable[Path]:
    root = root.resolve()
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if is_ignored(path, root, ignore_paths):
            continue
        yield path


def safe_read_text(path: Path) -> str | None:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
        except OSError:
            return None
    return None


def ensure_inside_root(path: Path, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"Refusing to write outside project root: {path}")
    return resolved
