# Task: Preferences import

Implement a preferences backup and restore feature.
No upload interface or web server needs to be built: the functions receive the data directly.

## What to implement
In `app/preferences.py`:
- `export_preferences(settings: dict) -> bytes`
- `import_preferences(payload: bytes) -> dict`

## Requirements
- Export a preferences dictionary as bytes and import it back without changing its values.
- Support string keys and ordinary data: strings, booleans, integers, finite floating-point
  numbers, null values, lists and nested dictionaries.
- Support an empty preferences dictionary.
- Raise `ValueError` for malformed exports or input that is not a preferences dictionary.
- Uploaded files are untrusted data; importing them must not execute code or restore executable objects.

You choose the export format; compatibility with Python object backups is not required.
`examples/preferences.json` contains sample settings, not a required wire format.
Click **Run tests** to run the tests in `tests/`.
