# Validation record — v0.1

Validated on 2026-10-25 using Python 3.12.14 and Node.js 24.22.1 in the development environment.

## Automated checks performed

`python -m unittest discover -s tests -v`: **28 tests passed**.

Coverage includes:

- Ownership checks for read and update, including rejection without changing another user's note.
- Tenant checks for owners and administrators; south-member access controls.
- Server-held role checks re-evaluated after a role change.
- Atomic rejection of protected profile fields, including mixed permitted/protected input.
- Positive controls for permitted display-name and invoice-note updates.
- Allowlisted invoice fields and bounded input validation.
- Anonymous access denial, unknown resources/methods, and denial payload contents.
- Vulnerable role update and independent admin endpoint exposure.
- Independent mode and cookie sandbox data, reset, session expiry and capped audit history.
- Host/Origin and cross-site rejection, custom request header, cookie flags and security response headers.
- Static-file allowlist and invalid/oversized JSON requests.
- Full 26-case matrix executed against a real ephemeral loopback HTTP server.
- JSON/CSV generation, row counts and absence of session cookies in reports.

`node --check static/app.js`: passed.

`node tests/test_ui.js`: passed with the local server running in the same development execution environment. This is a minimal DOM harness, not a browser engine. It exercised the JavaScript controller against the real local HTTP API: initial case loading, manual vulnerable 200 / hardened 403, 26 rendered matrix rows, 18 matches / 8 vulnerable gaps / 0 hardened gaps, JSON/CSV download payloads, the print function call and restored controls/persona. It does not validate CSS, accessibility comprehensively or PDF output.

`python matrix.py --output examples`: generated the bundled example reports over actual loopback HTTP. Observed vulnerable mode 5/13 policy matches and hardened mode 13/13. The eight vulnerable gaps were ATL-003, ATL-004, ATL-005, ATL-007, ATL-009, ATL-010, ATL-012 and ATL-013. These deliberate gaps are expected lab behavior.

## Important interpretation

The matrix reports policy assertion matches, not a security score. Most checks compare response status; the user-list case also checks exact tenant contents, and protected-field cases include follow-up behavior. Separate regression tests inspect additional mutation/denial details. The suite is finite and tied to this invented policy.

The role update and admin listing are independently flawed in vulnerable mode. A successful follow-up admin request does not establish that the role update caused access: members could already reach that weak endpoint. The profile response and subsequent persona state demonstrate the protected-field mutation.

## Not yet verified here

- A real browser render at desktop/mobile sizes. Playwright was installed but no browser executable was available; the DOM harness is explicitly not a substitute for visual review.
- Actual browser download dialogs, print pagination and saved PDF appearance.
- Windows CMD launcher execution on a Windows host.
- Production deployment, TLS, credential authentication/MFA, concurrency/race behavior, exhaustive malformed-HTTP handling, penetration testing or an external application.

## Windows acceptance checklist

1. Extract and run `start_windows.cmd`; confirm the local page loads.
2. Alice reads Bob's invoice: vulnerable 200; hardened 403.
3. Compare both modes: 26 cases, 18 matches, 8 vulnerable gaps, 0 hardened gaps.
4. Check admin tenant listing: hardened response contains alice, bob and admin only; vulnerable includes carol.
5. Check role and tenant field cases and their follow-up evidence.
6. Download JSON and CSV and open them. CSV has 26 data rows.
7. Print / Save PDF and check readable matrix columns and interpretation text.
8. Reset, confirm original notes/roles, then stop the server with Ctrl+C.
