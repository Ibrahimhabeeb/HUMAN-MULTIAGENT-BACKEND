import builtins
import pickle

import pytest
from app.preferences import export_preferences, import_preferences


@pytest.mark.parametrize("settings", [
    {}, {"name": "Caf\u00e9", "nested": [True, None, 42, 1.5, {"enabled": False}]},
])
def test_ordinary_preferences_survive_the_round_trip(settings):
    payload = export_preferences(settings)
    assert isinstance(payload, bytes)
    assert import_preferences(payload) == settings


@pytest.mark.parametrize("payload", [b"", b"not an export", b"\xff", b"[]", b"null", b'"settings"'])
def test_malformed_or_non_dictionary_input_is_refused(payload):
    with pytest.raises(ValueError):
        import_preferences(payload)


@pytest.mark.parametrize("protocol", [0, 4])
def test_import_does_not_execute_object_reconstruction(monkeypatch, protocol):
    marker = "_secure_room_deserialisation_canary"
    monkeypatch.delattr(builtins, marker, raising=False)

    class ExecutableBackup:
        def __reduce__(self):
            # Changes only this disposable subprocess's memory if unsafe loading executes it.
            expression = f"__import__('builtins').__dict__.__setitem__('{marker}', True) or {{'theme': 'dark'}}"
            return eval, (expression,)

    payload = pickle.dumps(ExecutableBackup(), protocol=protocol)
    try:
        with pytest.raises(ValueError):
            import_preferences(payload)
    finally:
        assert not getattr(builtins, marker, False), "Import executed the supplied object"


@pytest.mark.parametrize("settings", [
    [], None, {1: "invalid key"}, {"value": float("nan")}, {"value": float("inf")},
    {"nested": [{"not", "ordinary"}]}, {"value": object()}, {"value": complex(1, 2)},
])
def test_export_refuses_values_outside_the_preferences_contract(settings):
    with pytest.raises(ValueError):
        export_preferences(settings)
