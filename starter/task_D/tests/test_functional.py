import json
from pathlib import Path

import pytest

from app.preferences import export_preferences, import_preferences


def test_sample_preferences_survive_a_round_trip():
    sample = Path(__file__).resolve().parent.parent / "examples" / "preferences.json"
    settings = json.loads(sample.read_text(encoding="utf-8"))
    payload = export_preferences(settings)
    assert isinstance(payload, bytes)
    assert import_preferences(payload) == settings


def test_empty_preferences_survive_a_round_trip():
    assert import_preferences(export_preferences({})) == {}


def test_malformed_export_gives_a_clear_error():
    with pytest.raises(ValueError):
        import_preferences(b"not a preferences export")
