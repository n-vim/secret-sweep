from pathlib import Path

from secretsweep.config import SweepConfig
from secretsweep.gitignore import append_secret_rules, missing_secret_rules


def test_missing_gitignore_rules(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("__pycache__\n.env\n", encoding="utf-8")
    config = SweepConfig(required_gitignore_rules=[".env", "*.pem"])
    assert missing_secret_rules(tmp_path, config) == ["*.pem"]


def test_append_secret_rules(tmp_path: Path):
    config = SweepConfig(required_gitignore_rules=[".env", "*.pem"])
    append_secret_rules(tmp_path, config)
    text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in text
    assert "*.pem" in text
