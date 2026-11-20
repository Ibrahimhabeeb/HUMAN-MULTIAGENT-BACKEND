from services.fix_validation import invalid_python_edit


def test_reviewer_edit_cannot_leave_existing_names_undefined():
    before = "from app.db import get_db\n\ndef login(conn=get_db()):\n    return conn\n"
    after = "def login(conn=get_db()):\n    return conn\n"
    assert "F821" in invalid_python_edit("app/auth.py", before, after)


def test_reviewer_edit_cannot_remove_a_public_definition():
    before = "class Credentials:\n    pass\n\ndef login():\n    return True\n"
    after = "def login():\n    return True\n"
    assert "Credentials" in invalid_python_edit("app/auth.py", before, after)


def test_reviewer_edit_can_replace_code_inside_a_function():
    before = "def login(conn, username):\n    return conn.execute(f'SELECT * FROM users WHERE name = {username}')\n"
    after = "def login(conn, username):\n    return conn.execute('SELECT * FROM users WHERE name = ?', (username,))\n"
    assert invalid_python_edit("app/auth.py", before, after) is None


def test_reviewer_can_fix_one_issue_in_a_file_with_existing_undefined_names():
    before = (
        "def register(body: Credentials, conn=get_db()):\n    return body\n\n"
        "def login(conn, username):\n    return conn.execute(f'SELECT * FROM users WHERE name = {username}')\n"
    )
    after = before.replace(
        "conn.execute(f'SELECT * FROM users WHERE name = {username}')",
        "conn.execute('SELECT * FROM users WHERE name = ?', (username,))",
    )
    assert invalid_python_edit("app/auth.py", before, after) is None


def test_reviewer_cannot_add_another_undefined_name_to_an_already_broken_file():
    before = "def login(conn=get_db()):\n    return conn\n"
    after = "def login(conn=get_db()):\n    return missing_helper(conn)\n"
    assert "missing_helper" in invalid_python_edit("app/auth.py", before, after)
