def test_create_project_returns_its_info(client):
    project = client.post("/projects", json={"name": "demo", "user_id": "p1"}).json()
    assert len(project["id"]) == 36
    assert project["name"] == "demo"
    assert client.get(f"/projects/{project['id']}/files").json() == {}
    assert client.get(f"/projects/{project['id']}/state").json()["risks"] == []


def test_projects_can_be_listed_per_user(client):
    a = client.post("/projects", json={"name": "a", "user_id": "p1"}).json()["id"]
    client.post("/projects", json={"name": "b", "user_id": "p2"})
    assert [p["id"] for p in client.get("/projects?user_id=p1").json()] == [a]
    assert len(client.get("/projects").json()) == 2


def test_unknown_project_is_404(client):
    assert client.get("/projects/nope").status_code == 404
    assert client.get("/projects/nope/files").status_code == 404
    assert client.post("/projects/nope/sessions").status_code == 404


def test_a_project_can_have_several_sessions(client, pid):
    first = client.post(f"/projects/{pid}/sessions").json()
    second = client.post(f"/projects/{pid}/sessions").json()
    assert first["project_id"] == pid
    assert [s["id"] for s in client.get(f"/projects/{pid}/sessions").json()] == [first["id"], second["id"]]


def test_ending_a_session(client, pid, sid):
    ended = client.post(f"/sessions/{sid}/end").json()
    assert ended["ended_at"] is not None
    assert client.post(f"/sessions/{sid}/end").status_code == 409


def test_an_ended_session_cannot_change_anything(client, pid, sid):
    client.post(f"/sessions/{sid}/end")
    response = client.put(f"/projects/{pid}/files/new.py?session_id={sid}", json={"content": "x = 1"})
    assert response.status_code == 409
    assert "new.py" not in client.get(f"/projects/{pid}/files").json()


def test_a_session_from_another_project_is_refused(client, pid):
    other = client.post("/projects", json={"name": "other"}).json()["id"]
    other_sid = client.post(f"/projects/{other}/sessions").json()["id"]
    response = client.put(f"/projects/{pid}/files/new.py?session_id={other_sid}", json={"content": "x = 1"})
    assert response.status_code == 404


def test_changes_require_a_session(client, pid):
    assert client.put(f"/projects/{pid}/files/new.py", json={"content": "x = 1"}).status_code == 422
