import os, sqlite3, secrets, hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template, send_file, abort, flash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "trustvault.db")
UPLOAD_DIR = os.path.join(BASE, "private_files")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("TRUSTVAULT_SECRET", "change-this-in-production")
ALLOWED = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "png", "jpg", "jpeg"}
MAX_SIZE = 10 * 1024 * 1024

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def audit(user_id, document_id, action, success, details=""):
    with db() as c:
        c.execute("""INSERT INTO audit_logs(user_id,document_id,action,success,details,ip_address,created_at)
                     VALUES(?,?,?,?,?,?,?)""",
                  (user_id, document_id, action, 1 if success else 0, details,
                   request.remote_addr or "", datetime.utcnow().isoformat()))
        c.commit()

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    with db() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def can_read(user, doc):
    if not user or not doc: return False
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    with db() as c:
        return c.execute("""SELECT 1 FROM permissions
                            WHERE document_id=? AND user_id=? AND can_read=1""",
                         (doc["id"], user["id"])).fetchone() is not None

def can_edit(user, doc):
    if not user or not doc: return False
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    with db() as c:
        return c.execute("""SELECT 1 FROM permissions
                            WHERE document_id=? AND user_id=? AND can_edit=1""",
                         (doc["id"], user["id"])).fetchone() is not None

def get_doc(doc_id):
    with db() as c:
        return c.execute("""SELECT d.*, u.name owner_name
                            FROM documents d JOIN users u ON u.id=d.owner_id
                            WHERE d.id=?""", (doc_id,)).fetchone()

@app.route("/")
def index():
    if not current_user(): return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = hash_password(request.form["password"])
        with db() as c:
            u = c.execute("SELECT * FROM users WHERE email=? AND password_hash=?",
                          (email, password)).fetchone()
        if u:
            session["user_id"] = u["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    q = request.args.get("q","").strip()
    category = request.args.get("category","").strip()
    owner = request.args.get("owner","").strip()
    date = request.args.get("date","").strip()
    sql = """SELECT DISTINCT d.*, u.name owner_name FROM documents d
             JOIN users u ON u.id=d.owner_id
             LEFT JOIN permissions p ON p.document_id=d.id
             WHERE (d.owner_id=? OR p.user_id=? OR ?='admin')"""
    params = [u["id"], u["id"], u["role"]]
    if q:
        sql += " AND d.name LIKE ?"; params.append("%"+q+"%")
    if category:
        sql += " AND d.category=?"; params.append(category)
    if owner:
        sql += " AND u.name LIKE ?"; params.append("%"+owner+"%")
    if date:
        sql += " AND date(d.created_at)=date(?)"; params.append(date)
    sql += " ORDER BY d.created_at DESC"
    with db() as c:
        docs = c.execute(sql, params).fetchall()
        categories = c.execute("SELECT DISTINCT category FROM documents ORDER BY category").fetchall()
    return render_template("dashboard.html", user=u, docs=docs, categories=categories)

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    u = current_user()
    if request.method == "POST":
        f = request.files.get("file")
        name = request.form.get("name","").strip()
        category = request.form.get("category","General").strip()
        if not f or not f.filename:
            flash("Choose a file."); return redirect(url_for("upload"))
        ext = f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else ""
        if ext not in ALLOWED:
            flash("File type is not allowed."); return redirect(url_for("upload"))
        f.seek(0, os.SEEK_END); size = f.tell(); f.seek(0)
        if size > MAX_SIZE:
            flash("Maximum file size is 10 MB."); return redirect(url_for("upload"))
        stored = secrets.token_hex(24) + "." + ext
        f.save(os.path.join(UPLOAD_DIR, stored))
        with db() as c:
            cur = c.execute("""INSERT INTO documents(name,original_name,category,owner_id,storage_name,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?)""",
                            (name or secure_filename(f.filename), secure_filename(f.filename),
                             category, u["id"], stored, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
            doc_id = cur.lastrowid
            c.commit()
        audit(u["id"], doc_id, "UPLOAD", True, "Document uploaded")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")

@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    u = current_user(); doc = get_doc(doc_id)
    if not doc:
        abort(404)
    if not can_read(u, doc):
        audit(u["id"], doc_id, "DOWNLOAD", False, "Permission denied")
        abort(403)
    path = os.path.join(UPLOAD_DIR, doc["storage_name"])
    if not os.path.isfile(path):
        audit(u["id"], doc_id, "DOWNLOAD", False, "Stored file missing")
        abort(404)
    audit(u["id"], doc_id, "DOWNLOAD", True, "Document downloaded")
    return send_file(path, as_attachment=True, download_name=doc["original_name"])

@app.route("/documents/<int:doc_id>/edit", methods=["GET","POST"])
@login_required
def edit(doc_id):
    u = current_user(); doc = get_doc(doc_id)
    if not doc: abort(404)
    if not can_edit(u, doc):
        audit(u["id"], doc_id, "EDIT", False, "Permission denied")
        abort(403)
    if request.method == "POST":
        name = request.form["name"].strip()
        category = request.form["category"].strip()
        with db() as c:
            c.execute("UPDATE documents SET name=?,category=?,updated_at=? WHERE id=?",
                      (name, category, datetime.utcnow().isoformat(), doc_id))
            c.commit()
        audit(u["id"], doc_id, "EDIT", True, "Metadata updated")
        return redirect(url_for("dashboard"))
    return render_template("edit.html", doc=doc)

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    u = current_user(); doc = get_doc(doc_id)
    if not doc: abort(404)
    if not can_edit(u, doc):
        audit(u["id"], doc_id, "DELETE", False, "Permission denied")
        abort(403)
    path = os.path.join(UPLOAD_DIR, doc["storage_name"])
    if os.path.isfile(path): os.remove(path)
    with db() as c:
        c.execute("DELETE FROM permissions WHERE document_id=?", (doc_id,))
        c.execute("DELETE FROM documents WHERE id=?", (doc_id,))
        c.commit()
    audit(u["id"], None, "DELETE", True, f"Document {doc_id} deleted")
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:doc_id>/permissions", methods=["GET","POST"])
@login_required
def permissions(doc_id):
    u = current_user(); doc = get_doc(doc_id)
    if not doc: abort(404)
    if u["role"] != "admin" and doc["owner_id"] != u["id"]:
        audit(u["id"], doc_id, "PERMISSION_CHANGE", False, "Owner/admin required")
        abort(403)
    if request.method == "POST":
        user_id = int(request.form["user_id"])
        can_read_v = 1 if request.form.get("can_read") else 0
        can_edit_v = 1 if request.form.get("can_edit") else 0
        with db() as c:
            c.execute("""INSERT INTO permissions(document_id,user_id,can_read,can_edit,granted_at)
                         VALUES(?,?,?,?,?)
                         ON CONFLICT(document_id,user_id) DO UPDATE SET
                         can_read=excluded.can_read, can_edit=excluded.can_edit, granted_at=excluded.granted_at""",
                      (doc_id,user_id,can_read_v,can_edit_v,datetime.utcnow().isoformat()))
            c.commit()
        audit(u["id"], doc_id, "PERMISSION_CHANGE", True, f"Granted/updated user {user_id}")
        return redirect(url_for("permissions", doc_id=doc_id))
    with db() as c:
        users = c.execute("SELECT id,name,email,role FROM users WHERE id!=? ORDER BY name",(u["id"],)).fetchall()
        perms = c.execute("""SELECT p.*,u.name,u.email FROM permissions p JOIN users u ON u.id=p.user_id
                             WHERE p.document_id=? ORDER BY u.name""",(doc_id,)).fetchall()
    return render_template("permissions.html", doc=doc, users=users, perms=perms)

@app.route("/documents/<int:doc_id>/permissions/<int:user_id>/revoke", methods=["POST"])
@login_required
def revoke(doc_id,user_id):
    u=current_user(); doc=get_doc(doc_id)
    if not doc: abort(404)
    if u["role"]!="admin" and doc["owner_id"]!=u["id"]: abort(403)
    with db() as c:
        c.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?",(doc_id,user_id))
        c.commit()
    audit(u["id"],doc_id,"PERMISSION_REVOKE",True,f"Revoked user {user_id}")
    return redirect(url_for("permissions",doc_id=doc_id))

@app.route("/admin/audit")
@login_required
def admin_audit():
    u=current_user()
    if u["role"]!="admin": abort(403)
    with db() as c:
        logs=c.execute("""SELECT a.*,u.name user_name,d.name document_name
                          FROM audit_logs a JOIN users u ON u.id=a.user_id
                          LEFT JOIN documents d ON d.id=a.document_id
                          ORDER BY a.id DESC LIMIT 500""").fetchall()
    return render_template("audit.html",logs=logs)

def init_db():
    with db() as c:
        c.executescript(open(os.path.join(BASE,"schema.sql"),encoding="utf8").read())
        count=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count==0:
            users=[
                ("Admin User","admin@trustvault.local","admin","Admin@123"),
                ("Owner User","owner@trustvault.local","owner","Owner@123"),
                ("Viewer User","viewer@trustvault.local","viewer","Viewer@123"),
                ("Other Viewer","other@trustvault.local","viewer","Viewer@456")
            ]
            for name,email,role,pw in users:
                c.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                          (name,email,hash_password(pw),role))
            c.commit()

init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)