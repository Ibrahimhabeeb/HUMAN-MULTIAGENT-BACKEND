import pytest


def files(client, pid):
    return client.get(f"/projects/{pid}/files").json()


def test_initial_files_get_their_parent_folders(client, pid):
    tree = files(client, pid)
    assert tree["app"] == {"type": "folder"}
    assert tree["app/auth.py"]["type"] == "file"


def test_read_a_file(client, pid):
    node = client.get(f"/projects/{pid}/files/app/auth.py").json()
    assert node["content"].startswith("def login")
    assert client.get(f"/projects/{pid}/files/missing.py").status_code == 404
    assert client.get(f"/projects/{pid}/files/app").status_code == 404  # a folder, not a file


def test_write_creates_then_saves(client, pid, sid):
    url = f"/projects/{pid}/files/app/utils/validators.py?session_id={sid}"
    assert client.put(url, json={"content": "v1"}).status_code == 200
    client.put(url, json={"content": "v2"})

    tree = files(client, pid)
    assert tree["app/utils"] == {"type": "folder"}
    assert tree["app/utils/validators.py"]["content"] == "v2"


def test_cannot_write_over_a_folder_or_inside_a_file(client, pid, sid):
    assert client.put(f"/projects/{pid}/files/app?session_id={sid}", json={"content": "x"}).status_code == 409
    assert client.put(f"/projects/{pid}/files/main.py/x.py?session_id={sid}", json={"content": "x"}).status_code == 409


def test_create_folder(client, pid, sid):
    assert client.post(f"/projects/{pid}/folders?session_id={sid}", json={"path": "docs"}).status_code == 201
    assert files(client, pid)["docs"] == {"type": "folder"}
    assert client.post(f"/projects/{pid}/folders?session_id={sid}", json={"path": "docs"}).status_code == 409


def test_delete_a_folder_removes_everything_inside(client, pid, sid):
    assert client.delete(f"/projects/{pid}/files/app?session_id={sid}").status_code == 204
    tree = files(client, pid)
    assert "app" not in tree and "app/auth.py" not in tree
    assert client.delete(f"/projects/{pid}/files/app?session_id={sid}").status_code == 404


def test_rename_a_folder_moves_its_contents(client, pid, sid):
    body = {"from_path": "app", "to_path": "src/app"}
    assert client.post(f"/projects/{pid}/files/rename?session_id={sid}", json=body).status_code == 204
    tree = files(client, pid)
    assert tree["src/app/auth.py"]["content"].startswith("def login")
    assert "app/auth.py" not in tree


@pytest.mark.parametrize(
    "body, status",
    [
        ({"from_path": "nope.py", "to_path": "x.py"}, 404),
        ({"from_path": "main.py", "to_path": "app/auth.py"}, 409),
        ({"from_path": "app", "to_path": "app/inner"}, 409),
    ],
)
def test_rename_errors(client, pid, sid, body, status):
    assert client.post(f"/projects/{pid}/files/rename?session_id={sid}", json=body).status_code == status


def test_replace_all_files(client, pid, sid):
    body = {"files": {"solution/answer.py": {"type": "file", "content": "print(1)"}}}
    response = client.put(f"/projects/{pid}/files?session_id={sid}", json=body)
    assert response.status_code == 200
    assert set(files(client, pid)) == {"solution", "solution/answer.py"}


def test_files_are_shared_by_all_sessions_of_a_project(client, pid, sid):
    other_sid = client.post(f"/projects/{pid}/sessions").json()["id"]
    client.put(f"/projects/{pid}/files/shared.py?session_id={sid}", json={"content": "from session 1"})
    client.put(f"/projects/{pid}/files/shared.py?session_id={other_sid}", json={"content": "from session 2"})
    assert files(client, pid)["shared.py"]["content"] == "from session 2"


def test_projects_do_not_share_files(client, pid, sid):
    other = client.post("/projects", json={"name": "other"}).json()["id"]
    client.put(f"/projects/{pid}/files/only-here.py?session_id={sid}", json={"content": "x"})
    assert "only-here.py" not in files(client, other)


@pytest.mark.parametrize("bad_path", ["../secrets.txt", "app/../../x.py", "/etc/passwd", "a//b.py", "C:\\x.py", "a/./b.py"])
def test_unsafe_paths_are_rejected(client, pid, sid, bad_path):
    response = client.put(f"/projects/{pid}/files?session_id={sid}", json={"files": {bad_path: {"type": "file"}}})
    assert response.status_code == 422
    assert "main.py" in files(client, pid)  # nothing changed


def test_unsafe_paths_in_a_new_project_are_rejected(client):
    body = {"name": "evil", "files": {"../outside.py": {"type": "file", "content": "x"}}}
    assert client.post("/projects", json=body).status_code == 422
