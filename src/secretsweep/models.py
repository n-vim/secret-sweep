from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 3,
            Severity.HIGH: 7,
            Severity.CRITICAL: 12,
        }[self]


class FindingKind(str, Enum):
    SECRET = "secret"
    RISKY_FILE = "risky-file"
    GITIGNORE = "gitignore"
    ENVIRONMENT = "environment"
    CONFIG = "config"


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    column: int | None = None

    def display(self) -> str:
        if self.line is None:
            return self.path
        if self.column is None:
            return f"{self.path}:{self.line}"
        return f"{self.path}:{self.line}:{self.column}"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    kind: FindingKind
    location: Location
    message: str
    masked_value: str | None = None
    fingerprint: str | None = None
    suggestion: str | None = None
    context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "kind": self.kind.value,
            "location": {
                "path": self.location.path,
                "line": self.location.line,
                "column": self.location.column,
                "display": self.location.display(),
            },
            "message": self.message,
            "masked_value": self.masked_value,
            "fingerprint": self.fingerprint,
            "suggestion": self.suggestion,
            "context": self.context,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    risky_files: int = 0
    secrets_found: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "risky_files": self.risky_files,
            "secrets_found": self.secrets_found,
        }


@dataclass
class ProjectReport:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    ignored_paths: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def risk_level(self) -> str:
        severities = {finding.severity for finding in self.findings}
        if Severity.CRITICAL in severities:
            return "critical"
        if Severity.HIGH in severities:
            return "high"
        if Severity.MEDIUM in severities or self.score < 80:
            return "medium"
        return "low"

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def by_kind(self) -> dict[str, int]:
        counts = {kind.value: 0 for kind in FindingKind}
        for finding in self.findings:
            counts[finding.kind.value] += 1
        return counts

    def top_findings(self, limit: int = 10) -> list[Finding]:
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        return sorted(
            self.findings,
            key=lambda item: (severity_order[item.severity], item.location.path, item.location.line or 0),
        )[:limit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "score": self.score,
            "risk_level": self.risk_level,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.by_severity(),
                "by_kind": self.by_kind(),
            },
            "stats": self.stats.to_dict(),
            "ignored_paths": self.ignored_paths,
            "findings": [finding.to_dict() for finding in self.findings],
        }
