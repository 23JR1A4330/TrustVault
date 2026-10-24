import os, tempfile, pytest
from app import app, init_db, db, hash_password

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB", str(tmp_path / "test.db"))
    monkeypatch.setattr("app.UPLOAD_DIR", str(tmp_path / "files"))
    os.makedirs(str(tmp_path / "files"), exist_ok=True)
    init_db()
    with app.test_client() as c:
        yield c

def login(c, email, password):
    return c.post("/login", data={"email":email,"password":password}, follow_redirects=True)

def make_doc():
    with db() as c:
        owner = c.execute("SELECT id FROM users WHERE email='owner@trustvault.local'").fetchone()["id"]
        c.execute("""INSERT INTO documents(name,original_name,category,owner_id,storage_name,created_at,updated_at)
                     VALUES('Private','private.txt','HR',?,'secret.txt','now','now')""",(owner,))
        c.commit()
        return c.execute("SELECT id FROM documents WHERE name='Private'").fetchone()["id"]

def test_viewer_cannot_download_without_permission(client):
    doc_id=make_doc()
    assert login(client,"viewer@trustvault.local","Viewer@123").status_code == 200
    r=client.get(f"/documents/{doc_id}/download")
    assert r.status_code == 403

def test_viewer_cannot_edit_without_permission(client):
    doc_id=make_doc()
    login(client,"viewer@trustvault.local","Viewer@123")
    r=client.post(f"/documents/{doc_id}/edit", data={"name":"changed","category":"HR"})
    assert r.status_code == 403

def test_revoked_permission_blocks_download(client):
    doc_id=make_doc()
    with db() as c:
        viewer=c.execute("SELECT id FROM users WHERE email='viewer@trustvault.local'").fetchone()["id"]
        c.execute("INSERT INTO permissions(document_id,user_id,can_read,can_edit,granted_at) VALUES(?,?,?,?,?)",
                  (doc_id,viewer,1,0,"now"))
        c.commit()
    login(client,"viewer@trustvault.local","Viewer@123")
    # permission is removed immediately
    with db() as c:
        c.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?",(doc_id,viewer))
        c.commit()
    assert client.get(f"/documents/{doc_id}/download").status_code == 403
