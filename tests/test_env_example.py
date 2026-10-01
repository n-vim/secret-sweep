from pathlib import Path

from secretsweep.env_example import build_env_example_from_values, create_env_example, parse_env_file


def test_parse_env_file(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("API_KEY=real-secret\nDEBUG=true\n# comment\n", encoding="utf-8")
    values = parse_env_file(env)
    assert values["API_KEY"] == "real-secret"
    assert values["DEBUG"] == "true"


def test_build_env_example_masks_secret_values():
    text = build_env_example_from_values({"API_KEY": "real", "DEBUG": "true"})
    assert "API_KEY=change-me" in text
    assert "DEBUG=false" in text
    assert "real" not in text


def test_create_env_example(tmp_path: Path):
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://user:pass@host/db\n", encoding="utf-8")
    target = create_env_example(tmp_path)
    assert target.exists()
    assert "DATABASE_URL=https://example.com" in target.read_text(encoding="utf-8")
