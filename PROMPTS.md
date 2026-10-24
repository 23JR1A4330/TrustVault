# AI Usage Log

> Replace these example entries with the prompts and actual commit hashes from your own work. Do not claim a prompt or commit that did not happen.

## 2026-10-21 — Project structure
Prompt summary: Asked for a minimal secure document-sharing architecture with per-document permissions.
Output: Suggested Flask/SQLite structure and document/permission/audit tables.
What was wrong: The first design treated UI visibility as part of access control.
What I changed: Kept authorization entirely on the server and documented it in THREATS.md.
Commit: TODO

## 2026-10-21 — Authorization
Prompt summary: Asked how to secure a document download endpoint.
Output: Suggested checking login status and then returning the file.
What was wrong: Authentication alone does not prove authorization for a specific document.
What I changed: Added `can_read(user, doc)` before every file response.
Commit: TODO

## 2026-10-22 — IDOR testing
Prompt summary: Asked for tests against document-ID manipulation.
Output: Suggested testing only the normal UI.
What was wrong: UI tests do not prove the API rejects direct object-ID changes.
What I changed: Added an integration test that directly calls another document's download endpoint.
Commit: TODO

## 2026-10-23 — Audit trail
Prompt summary: Asked how to log successful and failed document access.
Output: Suggested logging successful downloads only.
What was wrong: The challenge explicitly requires refused attempts to be recorded.
What I changed: Added audit events before returning 403 for denied downloads.
Commit: TODO

## 2026-10-24 — Revocation
Prompt summary: Asked how to make permission revocation immediate.
Output: Suggested issuing a long-lived signed download URL.
What was wrong: A long-lived URL could continue working after revocation.
What I changed: Downloads require a fresh permission check on every request and no public file URLs are issued.
Commit: TODO
