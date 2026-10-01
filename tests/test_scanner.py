from pathlib import Path

from secretsweep.config import SweepConfig
from secretsweep.models import Severity
from secretsweep.scanner import SecretScanner


def test_scanner_finds_secret_and_masks_value(tmp_path: Path):
    sample = tmp_path / "app.py"
    sample.write_text("TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'\n", encoding="utf-8")
    report = SecretScanner(SweepConfig(scan_gitignore=False)).scan(tmp_path)
    assert report.stats.secrets_found == 1
    finding = report.findings[0]
    assert finding.rule_id == "github-token"
    assert finding.masked_value is not None
    assert "abcdefghijklmnopqrstuvwxyz" not in finding.masked_value
    assert finding.location.line == 1


def test_scanner_finds_risky_env_file(tmp_path: Path):
    (tmp_path / ".env").write_text("API_KEY=secret-value-for-local\n", encoding="utf-8")
    report = SecretScanner(SweepConfig(scan_gitignore=False, scan_secret_patterns=False)).scan(tmp_path)
    assert any(f.rule_id == "risky-file-.env" for f in report.findings)
    assert report.risk_level in {"high", "critical"}


def test_scanner_respects_allowed_rule(tmp_path: Path):
    (tmp_path / "fixture.txt").write_text("sk_test_1234567890abcdefghijklmnop\n", encoding="utf-8")
    config = SweepConfig(scan_gitignore=False, allowed_rules=["stripe-secret-key"])
    report = SecretScanner(config).scan(tmp_path)
    assert not any(f.rule_id == "stripe-secret-key" for f in report.findings)


def test_scanner_missing_gitignore_rules(tmp_path: Path):
    report = SecretScanner(SweepConfig(required_gitignore_rules=[".env"])).scan(tmp_path)
    assert any(f.rule_id == "missing-gitignore-secret-rules" for f in report.findings)
    assert any(f.severity == Severity.MEDIUM for f in report.findings)
