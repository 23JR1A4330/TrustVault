CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer'))
);
CREATE TABLE IF NOT EXISTS documents(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 original_name TEXT NOT NULL,
 category TEXT NOT NULL,
 owner_id INTEGER NOT NULL,
 storage_name TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(owner_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS permissions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 document_id INTEGER NOT NULL,
 user_id INTEGER NOT NULL,
 can_read INTEGER NOT NULL DEFAULT 0,
 can_edit INTEGER NOT NULL DEFAULT 0,
 granted_at TEXT NOT NULL,
 UNIQUE(document_id,user_id),
 FOREIGN KEY(document_id) REFERENCES documents(id),
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 document_id INTEGER,
 action TEXT NOT NULL,
 success INTEGER NOT NULL,
 details TEXT,
 ip_address TEXT,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
