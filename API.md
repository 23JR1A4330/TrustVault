# API / Route Authorization

| Route | Method | Allowed |
|---|---|---|
| /login | POST | Public |
| /dashboard | GET | Authenticated |
| /upload | POST | Admin, Owner |
| /documents/{id}/download | GET | Owner, Admin, explicit Read |
| /documents/{id}/edit | POST | Owner, Admin, explicit Edit |
| /documents/{id}/delete | POST | Owner, Admin |
| /documents/{id}/permissions | GET/POST | Owner, Admin |
| /documents/{id}/permissions/{user}/revoke | POST | Owner, Admin |
| /admin/audit | GET | Admin |

Authorization is enforced on the server, not by UI visibility.
