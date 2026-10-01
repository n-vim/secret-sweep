from pathlib import Path

import pytest

from secretsweep.utils import ensure_inside_root, relative_to_root


def test_relative_to_root(tmp_path: Path):
    file_path = tmp_path / "src" / "app.py"
    file_path.parent.mkdir()
    file_path.write_text("", encoding="utf-8")
    assert relative_to_root(file_path, tmp_path) == "src/app.py"


def test_ensure_inside_root_rejects_outside(tmp_path: Path):
    outside = tmp_path.parent / "outside.txt"
    with pytest.raises(ValueError):
        ensure_inside_root(outside, tmp_path)
