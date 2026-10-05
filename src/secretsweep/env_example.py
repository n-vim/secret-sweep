from __future__ import annotations

from pathlib import Path

SECRET_HINTS = ("SECRET", "TOKEN", "KEY", "PASSWORD", "PASS", "PRIVATE", "CLIENT_SECRET")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        if not key:
            continue
        values[key] = value.strip().strip('"\'')
    return values


def safe_placeholder(key: str) -> str:
    upper = key.upper()
    if any(hint in upper for hint in SECRET_HINTS):
        return "change-me"
    if "URL" in upper:
        return "https://example.com"
    if "PORT" in upper:
        return "8000"
    if upper in {"DEBUG", "DEV", "LOCAL"}:
        return "false"
    return ""


def build_env_example_from_values(values: dict[str, str]) -> str:
    lines = ["# Example environment variables", "# Copy this file to .env and fill in local values.", ""]
    for key in sorted(values):
        lines.append(f"{key}={safe_placeholder(key)}")
    return "\n".join(lines).rstrip() + "\n"


def create_env_example(root: Path, source_name: str = ".env", force: bool = False) -> Path:
    source = root / source_name
    target = root / ".env.example"
    if target.exists() and not force:
        return target
    values = parse_env_file(source)
    if not values:
        values = {
            "APP_ENV": "development",
            "DEBUG": "false",
            "API_KEY": "change-me",
        }
    target.write_text(build_env_example_from_values(values), encoding="utf-8")
    return target
