# Authorization Testing Lab

A local, intentionally vulnerable authorization lab with a matching hardened implementation. Explore ownership, tenant boundaries, admin permissions and protected profile fields, then export a matrix of expected versus observed behavior.

**Python 3.12 standard library only. No pip packages, API keys, database, Docker or external scan service.**

This is an educational application with synthetic records. It is not a scanner for other websites or a production authentication template. Keep it bound to loopback; do not publish the running vulnerable server or put it behind a public tunnel.

## Start on Windows

1. Extract the ZIP completely.
2. Open the `AuthorizationTestingLab` folder.
3. Double-click `start_windows.cmd`.
4. Open http://127.0.0.1:8820 if a browser does not open automatically.

Keep the console open. Press Ctrl+C there to stop the server.

From Windows CMD:

```cmd
py -3.12 server.py
```

If port 8820 is already in use:

```cmd
set AUTH_LAB_PORT=8821
py -3.12 server.py
```

Linux/macOS: `python3 server.py`. Set `AUTH_LAB_NO_BROWSER=1` to suppress opening a browser. The host is fixed to `127.0.0.1`; it is not configurable to a public interface. Use the supplied local origin directly, without a reverse proxy.

## Practice in this order

1. Keep **Alice** and **Vulnerable** selected. Send **Read Bob's invoice as Alice**. Expect HTTP 200 and Bob's synthetic record.
2. Switch to **Hardened** and send the same exercise. Expect HTTP 403.
3. Try the tenant, note-edit, admin-list and profile-field exercises. The UI sends real requests to the local API; it does not manufacture response codes.
4. For the role exercise, reset, select Alice and Vulnerable, assign `role: admin`, then inspect the current persona. In Hardened mode the field update is rejected with HTTP 400 and the role stays member. Weak mode also independently lacks the admin endpoint's role check; the follow-up does not prove that changing the role was necessary to reach that endpoint.
5. Select **Compare both modes**. Each of 13 cases runs in each implementation from fresh seed data. The comparison resets state before each case and after completion, restoring Alice.
6. Export JSON, matrix CSV, or Print / Save PDF. JSON contains per-case responses, checks and follow-up evidence. CSV contains one row per case with status and assertion results. The print view contains the comparison and interpretation limits; expand response evidence first if you also want it printed.

Expected default matrix:

| Implementation | Cases | Policy matches | Policy gaps |
| --- | ---: | ---: | ---: |
| Vulnerable | 13 | 5 | 8 |
| Hardened | 13 | 13 | 0 |
| Total | 26 | 18 | 8 |

**Policy gaps in vulnerable mode are expected learning evidence.** These are not test-runner failures. A match confirms only the listed assertions; the counts are not a security score.

## Intended policy

| Persona | Role | Tenant | Owned invoice |
| --- | --- | --- | --- |
| alice | member | north | 1001 |
| bob | member | north | 1002 |
| carol | member | south | 2001 |
| admin | admin | north | none |

- Members may read and edit their own invoices within their tenant.
- Tenant admins may read and edit invoices within their tenant.
- Admin user lists must require the admin role and return only that tenant's users.
- Profiles accept only `display_name`; `role`, `tenant`, `username` and arbitrary fields are not writable.
- Anonymous requests cannot use protected operations.
- Unknown operations are denied. Unknown invoices return 404; known forbidden invoices return 403. Object-existence hiding is outside this exercise.

The hardened implementation reads identity, role and tenant from server-held state on every request. It combines tenant and owner/admin checks; knowing an ID is insufficient. Profile fields are allowlisted before any mutation. Vulnerable mode deliberately skips ownership and tenant checks on invoices, role and tenant checks on user listings, and protection of role/tenant profile fields.

## Cases and evidence

| Case | Exercise | Intended result |
| --- | --- | --- |
| ATL-001 | Anonymous invoice read | 401 |
| ATL-002 | Owner reads own invoice | 200 |
| ATL-003 | Member reads peer invoice | 403 |
| ATL-004 | Member reads across tenants | 403 |
| ATL-005 | Member edits peer invoice | 403 |
| ATL-006 | Owner edits own invoice | 200 |
| ATL-007 | Member opens admin listing | 403 |
| ATL-008 | Tenant admin reads peer invoice | 200 |
| ATL-009 | Admin reads across tenants | 403 |
| ATL-010 | Tenant admin lists users | 200; exact north user set and tenant checks |
| ATL-011 | Member changes display name | 200 |
| ATL-012 | Member assigns own admin role | 400; subsequent admin request 403 |
| ATL-013 | Member assigns own tenant | 400; profile remains north |

Most matrix checks compare status codes. ATL-010, ATL-012 and ATL-013 also inspect content or follow-up behavior. Python regression tests additionally assert permitted mutations, rejected updates without side effects, fresh authority checks, input validation and denial payloads. Do not interpret a status-only match as a complete content/state audit.

## State and training identities

Persona selection intentionally simulates an authenticated identity; it has no passwords and is not a credential validation implementation. The lab session is an opaque random cookie identifying a browser sandbox. It is HttpOnly and SameSite=Strict, expires after two hours, and is not marked Secure because this lab uses loopback HTTP. That is not a production session design.

Each browser sandbox has independent vulnerable/hardened data. Tabs sharing the same session share data: run one comparison at a time and avoid simultaneous manual edits. Manual edits persist until reset, expiry or server restart. A refresh preserves the sandbox. The persona dropdown is a request selection; the next send switches to it. Reports remain historical snapshots after reset.

Up to 64 active sandboxes are allowed. Per-session decision history is capped at 200 entries. Profile strings are limited to 80 characters; invoice notes to 200; request bodies to 4096 bytes. State is in memory, and HTTP request logging is suppressed. Report downloads are written only when requested by the browser.

## Local API

All API calls require `X-Authorization-Lab: local`. Mutating operations require a JSON object and `Content-Type: application/json`. Requests must use the allowed local Host, and any Origin must be a local allowed origin. Cross-site fetch metadata is rejected; CORS is not enabled.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/state` | Initialize sandbox and load seed metadata/case definitions |
| POST | `/api/persona` | Select `{ "username": "alice" }`, bob, carol, admin, or null |
| POST | `/api/reset` | Restore both modes and Alice; clear decision history |
| GET | `/api/audit` | Latest 200 exercise decisions (not a persistent audit system) |
| GET | `/api/{mode}/me` | Current server-held persona |
| GET / PATCH | `/api/{mode}/invoices/{id}` | Read record or edit `{ "note": "..." }` |
| GET | `/api/{mode}/admin/users` | User listing exercise |
| PATCH | `/api/{mode}/profile` | Profile field binding exercise |

`mode` is `weak` or `hardened`. These controls isolate the training sandbox; they do not make the intentionally vulnerable application suitable for deployment.

## Validate and generate reports without the UI

From the project folder:

```cmd
py -3.12 -m unittest discover -s tests -v
py -3.12 matrix.py
```

`matrix.py` creates its own temporary server on an OS-assigned loopback port, runs 26 cases, stops it and writes `reports/authorization-matrix.json` and `.csv`. There is no remote-target option. Use `--output examples` to regenerate the bundled example reports. Only synthetic lab data and response decisions are included, with no session cookies.

Optional Node.js checks (Node is not needed to run the application):

```cmd
node --check static/app.js
node tests/test_ui.js
```

The controller smoke test requires the lab running on port 8820. It uses a minimal DOM harness, not a browser rendering engine. See `VALIDATION.md` for observed validation and remaining limits.

## Files

- `lab.py`: seed data, intended object policy, vulnerable/hardened operations, case definitions and assertions.
- `server.py`: fixed-loopback HTTP server, per-cookie sandboxes and request boundaries.
- `matrix.py`: ephemeral HTTP matrix runner and JSON/CSV exporter.
- `static/`: browser console, same-origin request runner and report rendering.
- `tests/`: policy/HTTP regressions and optional JavaScript controller smoke.
- `examples/`: generated synthetic matrix reports.

## Limits

This lab does not assess external sites, production authentication, MFA, TLS, CSRF comprehensively, concurrency/race behavior, database security, arbitrary routing frameworks, every possible authorization policy or information leak. It does not establish that a real application is secure. No external services, accounts or network targets are accessed by the exercises. OWASP reference links open only when you choose to visit them.

## References

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html): deny by default and check permissions on each request.
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html): explicitly allowlist writable fields.

This is an independent learning project, not an OWASP certification or an exhaustive implementation of those guides.
