from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .patterns import DEFAULT_IGNORE_DIRS, DEFAULT_SECRET_GITIGNORE_RULES, DEFAULT_TEXT_EXTENSIONS

try:  # pragma: no cover - tested through public behavior
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass
class SweepConfig:
    ignore_paths: list[str] = field(default_factory=lambda: sorted(DEFAULT_IGNORE_DIRS))
    include_extensions: list[str] = field(default_factory=lambda: sorted(DEFAULT_TEXT_EXTENSIONS))
    max_file_size: int = 1_000_000
    required_gitignore_rules: list[str] = field(default_factory=lambda: list(DEFAULT_SECRET_GITIGNORE_RULES))
    allowed_rules: list[str] = field(default_factory=list)
    fail_on: str = "critical"
    mask_visible: int = 4
    scan_gitignore: bool = True
    scan_risky_files: bool = True
    scan_secret_patterns: bool = True

    @classmethod
    def default(cls) -> "SweepConfig":
        return cls()

    def should_allow_rule(self, rule_id: str) -> bool:
        return rule_id in set(self.allowed_rules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ignore_paths": self.ignore_paths,
            "include_extensions": self.include_extensions,
            "max_file_size": self.max_file_size,
            "required_gitignore_rules": self.required_gitignore_rules,
            "allowed_rules": self.allowed_rules,
            "fail_on": self.fail_on,
            "mask_visible": self.mask_visible,
            "scan_gitignore": self.scan_gitignore,
            "scan_risky_files": self.scan_risky_files,
            "scan_secret_patterns": self.scan_secret_patterns,
        }


CONFIG_NAME = ".secretsweep.yaml"


def _basic_yaml_load(text: str) -> dict[str, Any]:
    """Small fallback parser for simple key/value lists when PyYAML is unavailable."""
    data: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value == "":
                data[key] = []
                current_key = key
            elif value.lower() in {"true", "false"}:
                data[key] = value.lower() == "true"
                current_key = None
            else:
                try:
                    data[key] = int(value)
                except ValueError:
                    data[key] = value.strip('"\'')
                current_key = None
        elif current_key and stripped.startswith("-"):
            item = stripped[1:].strip().strip('"\'')
            if isinstance(data.get(current_key), list):
                data[current_key].append(item)
    return data


def load_config(root: Path, explicit: Path | None = None) -> SweepConfig:
    config = SweepConfig.default()
    path = explicit or root / CONFIG_NAME
    if not path.exists():
        return config
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        loaded = yaml.safe_load(text) or {}
    else:
        loaded = _basic_yaml_load(text)
    if not isinstance(loaded, dict):
        return config
    for key, value in loaded.items():
        if not hasattr(config, key):
            continue
        current = getattr(config, key)
        if isinstance(current, list) and isinstance(value, list):
            setattr(config, key, [str(item) for item in value])
        elif isinstance(current, bool):
            setattr(config, key, bool(value))
        elif isinstance(current, int):
            try:
                setattr(config, key, int(value))
            except (TypeError, ValueError):
                pass
        elif isinstance(current, str):
            setattr(config, key, str(value))
    return config


def default_config_text() -> str:
    return """# SecretSweep configuration
ignore_paths:
  - .git
  - .venv
  - node_modules
  - dist
  - build
  - __pycache__
  - .pytest_cache

include_extensions:
  - .py
  - .js
  - .ts
  - .json
  - .yaml
  - .yml
  - .toml
  - .env
  - .md
  - .txt

max_file_size: 1000000
mask_visible: 4
fail_on: critical
scan_gitignore: true
scan_risky_files: true
scan_secret_patterns: true

required_gitignore_rules:
  - .env
  - .env.*
  - '!.env.example'
  - '*.pem'
  - '*.key'
  - id_rsa
  - id_ed25519

# Use allowed_rules only for intentional test fixtures.
allowed_rules: []
"""
