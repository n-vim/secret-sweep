from __future__ import annotations

from pathlib import Path

from .config import SweepConfig


def read_gitignore(root: Path) -> list[str]:
    path = root / ".gitignore"
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def missing_secret_rules(root: Path, config: SweepConfig) -> list[str]:
    existing = set(read_gitignore(root))
    missing = []
    for rule in config.required_gitignore_rules:
        if rule not in existing:
            missing.append(rule)
    return missing


def gitignore_block(config: SweepConfig) -> str:
    lines = ["", "# SecretSweep recommended secret rules"]
    lines.extend(config.required_gitignore_rules)
    return "\n".join(lines).strip() + "\n"


def append_secret_rules(root: Path, config: SweepConfig) -> Path:
    path = root / ".gitignore"
    existing = read_gitignore(root)
    existing_set = set(existing)
    missing = [rule for rule in config.required_gitignore_rules if rule not in existing_set]
    if not missing:
        return path
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    block = "\n# SecretSweep recommended secret rules\n" + "\n".join(missing) + "\n"
    path.write_text(current.rstrip() + "\n" + block, encoding="utf-8")
    return path
