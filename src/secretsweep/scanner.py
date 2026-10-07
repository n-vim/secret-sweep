from __future__ import annotations

from pathlib import Path

from .config import SweepConfig, load_config
from .gitignore import missing_secret_rules
from .masker import fingerprint, mask_line, mask_secret
from .models import Finding, FindingKind, Location, ProjectReport, ScanStats, Severity
from .patterns import DEFAULT_SECRET_PATTERNS, RISKY_FILE_NAMES, RISKY_SUFFIXES
from .utils import is_binary_file, iter_project_files, relative_to_root, safe_read_text, should_scan_file


class SecretScanner:
    def __init__(self, config: SweepConfig | None = None) -> None:
        self.config = config or SweepConfig.default()

    def scan(self, root: Path) -> ProjectReport:
        root = root.resolve()
        report = ProjectReport(root=root, stats=ScanStats(), ignored_paths=list(self.config.ignore_paths))

        if self.config.scan_gitignore:
            self._scan_gitignore(root, report)

        extensions = set(self.config.include_extensions)
        for path in iter_project_files(root, self.config.ignore_paths):
            try:
                size = path.stat().st_size
            except OSError:
                report.stats.files_skipped += 1
                continue
            if size > self.config.max_file_size:
                report.stats.files_skipped += 1
                continue
            rel = relative_to_root(path, root)
            if self.config.scan_risky_files:
                self._scan_risky_file(path, rel, report)
            if not should_scan_file(path, extensions):
                report.stats.files_skipped += 1
                continue
            if is_binary_file(path):
                report.stats.files_skipped += 1
                continue
            text = safe_read_text(path)
            if text is None:
                report.stats.files_skipped += 1
                continue
            report.stats.files_scanned += 1
            report.stats.bytes_scanned += size
            if self.config.scan_secret_patterns:
                self._scan_text(rel, text, report)
        return report

    def _scan_gitignore(self, root: Path, report: ProjectReport) -> None:
        missing = missing_secret_rules(root, self.config)
        if not missing:
            return
        report.findings.append(
            Finding(
                rule_id="missing-gitignore-secret-rules",
                title="Missing secret rules in .gitignore",
                severity=Severity.MEDIUM,
                kind=FindingKind.GITIGNORE,
                location=Location(path=".gitignore"),
                message="The repository is missing ignore rules for common secret files.",
                suggestion="Add these rules: " + ", ".join(missing),
                context="\n".join(missing),
            )
        )

    def _scan_risky_file(self, path: Path, rel: str, report: ProjectReport) -> None:
        name = path.name
        if name in RISKY_FILE_NAMES:
            severity, title, suggestion = RISKY_FILE_NAMES[name]
            report.stats.risky_files += 1
            report.findings.append(
                Finding(
                    rule_id=f"risky-file-{name}",
                    title=title,
                    severity=severity,
                    kind=FindingKind.RISKY_FILE,
                    location=Location(path=rel),
                    message=f"Risky file found: {rel}",
                    suggestion=suggestion,
                )
            )
            return
        for suffix, (severity, title, suggestion) in RISKY_SUFFIXES.items():
            if name.lower().endswith(suffix):
                report.stats.risky_files += 1
                report.findings.append(
                    Finding(
                        rule_id=f"risky-suffix-{suffix.lstrip('.')}",
                        title=title,
                        severity=severity,
                        kind=FindingKind.RISKY_FILE,
                        location=Location(path=rel),
                        message=f"Risky file extension found: {rel}",
                        suggestion=suggestion,
                    )
                )
                return

    def _scan_text(self, rel: str, text: str, report: ProjectReport) -> None:
        seen: set[tuple[str, str, str]] = set()
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            occupied_spans: list[tuple[int, int]] = []
            for pattern in DEFAULT_SECRET_PATTERNS:
                if self.config.should_allow_rule(pattern.rule_id):
                    continue
                for match in pattern.regex.finditer(line):
                    try:
                        raw = match.group(pattern.group)
                        start = match.start(pattern.group)
                        end = match.end(pattern.group)
                    except IndexError:
                        raw = match.group(0)
                        start = match.start()
                        end = match.end()
                    if not raw or len(raw.strip()) < 8:
                        continue
                    if any(start < used_end and end > used_start for used_start, used_end in occupied_spans):
                        continue
                    fp = fingerprint(f"{pattern.rule_id}:{raw}")
                    key = (pattern.rule_id, rel, fp)
                    if key in seen:
                        continue
                    seen.add(key)
                    occupied_spans.append((start, end))
                    masked = mask_secret(raw, visible=self.config.mask_visible)
                    report.stats.secrets_found += 1
                    report.findings.append(
                        Finding(
                            rule_id=pattern.rule_id,
                            title=pattern.title,
                            severity=pattern.severity,
                            kind=FindingKind.SECRET,
                            location=Location(path=rel, line=line_number, column=max(start + 1, 1)),
                            message=pattern.description or "A secret-like value was detected.",
                            masked_value=masked,
                            fingerprint=fp,
                            suggestion=pattern.suggestion,
                            context=mask_line(line, raw, masked),
                        )
                    )


def scan_path(root: Path, config_path: Path | None = None) -> ProjectReport:
    config = load_config(root.resolve(), config_path)
    return SecretScanner(config).scan(root)
