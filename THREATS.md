# TrustVault Threat Model

## 1. IDOR / object-level authorization
Attack: change a document ID in a URL to another document.
Protection: every document endpoint loads the document and checks the current user's ownership or explicit permission.
Test: viewer without permission receives 403.

## 2. Direct file access
Attack: guess a file URL and bypass the API.
Protection: files are stored outside a public/static directory and only returned by the authorized download endpoint.

## 3. Unauthorized edit/delete
Attack: call edit/delete endpoint directly without UI.
Protection: server-side `can_edit` check.
Test: unauthorized viewer receives 403.

## 4. Permission escalation
Attack: viewer calls permission API to grant access to another user.
Protection: only owner/admin can manage permissions.

## 5. Revoke bypass
Attack: keep using an old route after permission is revoked.
Protection: no permanent signed/public URLs; permission is checked for every download.

## 6. Upload abuse
Attack: upload unsupported or oversized files.
Protection: extension allowlist and 10 MB limit. Production should add MIME sniffing and malware scanning.

## 7. Path traversal
Attack: use a filename such as ../../secret.
Protection: generated random storage names are used instead of user filenames.

## 8. Audit tampering
Risk: an administrator or database operator could alter SQLite rows.
Current mitigation: application does not expose audit-edit/delete endpoints.
Known limitation: this demo does not provide WORM/immutable storage or hash chaining.
Production improvement: append-only external audit sink with integrity verification.

## 9. Search metadata leakage
Protection: search results are built from documents the current user is allowed to see; admins can see all.

## 10. Password/session security
Current demo uses SHA-256 for simplicity.
Known limitation: production must use a slow password hash such as Argon2id/bcrypt, secure cookie settings, CSRF protection and rate limiting.

## Accepted limitations
This challenge starter prioritizes the core authorization model. It does not implement SSO, MFA, malware scanning, immutable external audit storage, document versioning, recovery, or external sharing.
