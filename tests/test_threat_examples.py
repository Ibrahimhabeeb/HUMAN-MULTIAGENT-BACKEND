import pytest

from agents.threat_examples import extract


@pytest.mark.parametrize("code, name", [
    ("def login(conn):\n    return conn.execute('SELECT 1')", "login"),
    ("async def download(name):\n    return name", "download"),
    ("    if untrusted:", None),
    ("def login():\n    pass\ndef register_user():\n    pass", None),
])
def test_example_scope_names_only_a_single_parsable_function(code, name):
    reply = f'One risk.\n<risk-example path="app/auth.py">\n```python\n{code}\n```\n</risk-example>'
    text, example = extract(reply, {"app/auth.py"})
    assert text == "One risk."
    assert example["code"] == code.strip()
    assert example.get("function") == name


def test_an_example_for_an_unknown_file_is_not_published():
    text, example = extract('Risk.\n<risk-example path="elsewhere.py">\n```python\ndef login():\n    pass\n```\n</risk-example>', {"app/auth.py"})
    assert text == "Risk."
    assert example is None
