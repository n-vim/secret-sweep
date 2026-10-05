from __future__ import annotations

from dataclasses import dataclass
from re import Pattern
import re

from .models import Severity


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    title: str
    regex: Pattern[str]
    severity: Severity
    group: int = 0
    description: str = ""
    suggestion: str = "Move the value to an environment variable and rotate it if it was committed."


DEFAULT_SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        rule_id="aws-access-key-id",
        title="Possible AWS access key ID",
        regex=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        suggestion="Rotate the AWS key and remove it from repository history if it was committed.",
    ),
    SecretPattern(
        rule_id="github-token",
        title="Possible GitHub token",
        regex=re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"),
        severity=Severity.CRITICAL,
        suggestion="Revoke the GitHub token and use GitHub Actions secrets or local environment variables.",
    ),
    SecretPattern(
        rule_id="slack-token",
        title="Possible Slack token",
        regex=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        severity=Severity.HIGH,
        suggestion="Revoke the Slack token and load it from a secure secret store.",
    ),
    SecretPattern(
        rule_id="stripe-secret-key",
        title="Possible Stripe secret key",
        regex=re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"),
        severity=Severity.CRITICAL,
        suggestion="Rotate the Stripe key and keep it out of source control.",
    ),
    SecretPattern(
        rule_id="google-api-key",
        title="Possible Google API key",
        regex=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity=Severity.HIGH,
        suggestion="Restrict and rotate the Google API key if it is real.",
    ),
    SecretPattern(
        rule_id="npm-token",
        title="Possible npm token",
        regex=re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
        severity=Severity.HIGH,
        suggestion="Revoke the npm token and move publishing credentials to CI secrets.",
    ),
    SecretPattern(
        rule_id="jwt-token",
        title="Possible JWT token",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        severity=Severity.MEDIUM,
        suggestion="Avoid storing JWTs in code, logs, fixtures, or documentation.",
    ),
    SecretPattern(
        rule_id="private-key-block",
        title="Private key block marker",
        regex=re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        suggestion="Remove private keys from the repository and rotate anything that used them.",
    ),
    SecretPattern(
        rule_id="database-url-password",
        title="Database URL with inline password",
        regex=re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s:/@]+:[^\s/@]+@[^\s]+",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        suggestion="Move database credentials to environment variables or a secret manager.",
    ),
    SecretPattern(
        rule_id="basic-auth-url",
        title="URL with inline username and password",
        regex=re.compile(r"\bhttps?://[^\s:/@]+:[^\s/@]+@[^\s]+", re.IGNORECASE),
        severity=Severity.HIGH,
        suggestion="Do not store credentials inside URLs. Use environment variables instead.",
    ),
    SecretPattern(
        rule_id="assignment-secret",
        title="Possible hardcoded secret assignment",
        regex=re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"]([^'\"]{12,})['\"]"
        ),
        severity=Severity.MEDIUM,
        group=2,
        suggestion="Replace hardcoded secret-like values with environment variables.",
    ),
    SecretPattern(
        rule_id="bearer-token",
        title="Possible bearer token",
        regex=re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-]{24,})\b"),
        severity=Severity.MEDIUM,
        group=1,
        suggestion="Avoid storing bearer tokens in source files, docs, or test fixtures.",
    ),
)


RISKY_FILE_NAMES: dict[str, tuple[Severity, str, str]] = {
    ".env": (
        Severity.HIGH,
        "Environment file committed or present in repository",
        "Add .env to .gitignore and keep only a safe .env.example file.",
    ),
    ".env.local": (
        Severity.HIGH,
        "Local environment file committed or present in repository",
        "Add .env.local to .gitignore and keep local secrets outside source control.",
    ),
    ".env.production": (
        Severity.CRITICAL,
        "Production environment file found",
        "Remove production secrets from the repository and rotate exposed credentials.",
    ),
    "id_rsa": (
        Severity.CRITICAL,
        "Private SSH key file found",
        "Remove private keys from the repository and rotate the key pair.",
    ),
    "id_ed25519": (
        Severity.CRITICAL,
        "Private SSH key file found",
        "Remove private keys from the repository and rotate the key pair.",
    ),
}

RISKY_SUFFIXES: dict[str, tuple[Severity, str, str]] = {
    ".pem": (
        Severity.HIGH,
        "PEM file found",
        "Review this file. Private certificates or keys should not be committed.",
    ),
    ".key": (
        Severity.CRITICAL,
        "Key file found",
        "Remove private key files from the repository and rotate affected credentials.",
    ),
    ".p12": (
        Severity.HIGH,
        "PKCS#12 certificate archive found",
        "Keep certificate archives out of source control unless they are public test fixtures.",
    ),
    ".pfx": (
        Severity.HIGH,
        "PFX certificate archive found",
        "Keep certificate archives out of source control unless they are public test fixtures.",
    ),
}

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    ".nuxt",
}

DEFAULT_SECRET_GITIGNORE_RULES = [
    ".env",
    ".env.*",
    "!.env.example",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
]

DEFAULT_TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".example",
    ".md",
    ".txt",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".php",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".xml",
    ".html",
    ".css",
    ".scss",
    ".dockerfile",
}
