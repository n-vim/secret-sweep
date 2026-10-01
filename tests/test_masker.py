from secretsweep.masker import fingerprint, mask_line, mask_secret


def test_mask_secret_hides_middle():
    masked = mask_secret("ghp_abcdefghijklmnopqrstuvwxyz1234567890")
    assert masked.startswith("ghp_")
    assert masked.endswith("7890")
    assert "abcdefghijklmnopqrstuvwxyz" not in masked


def test_fingerprint_is_stable_and_short():
    assert fingerprint("secret") == fingerprint("secret")
    assert len(fingerprint("secret")) == 16


def test_mask_line_replaces_secret():
    line = "TOKEN=supersecretvalue"
    assert "supersecretvalue" not in mask_line(line, "supersecretvalue", "supe****alue")
