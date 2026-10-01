from pathlib import Path

from secretsweep.config import SweepConfig
from secretsweep.reports import render_html, render_json, render_markdown
from secretsweep.scanner import SecretScanner


def test_reports_render_all_formats(tmp_path: Path):
    (tmp_path / "app.py").write_text("PASSWORD = 'not-a-real-password-value'\n", encoding="utf-8")
    report = SecretScanner(SweepConfig(scan_gitignore=False)).scan(tmp_path)
    markdown = render_markdown(report)
    json_text = render_json(report)
    html = render_html(report)
    assert "# SecretSweep Security Report" in markdown
    assert '"risk_level"' in json_text
    assert "<html" in html
    assert "not-a-real-password-value" not in markdown
    assert "not-a-real-password-value" not in html
