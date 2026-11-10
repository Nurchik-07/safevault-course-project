# SafeVault

SafeVault is a small ASP.NET Core course project with account registration, sign-in, private notes, and an admin-only user lookup. It uses ASP.NET Core Identity and SQLite. No demo user or password is committed.

## Run locally

Install the .NET 10 SDK, then run these commands from the repository root. Use the local HTTPS development certificate that ships with the SDK.

```powershell
dotnet dev-certs https
dotnet run --project src/SafeVault --urls https://localhost:7043
```

Register a member at `/register` and sign in at `/login`. To create a local administrator, configure all three values before starting the app. Use a new administrator username and your own strong password.

```powershell
$env:SafeVault__AdminUsername = 'vault_admin'
$env:SafeVault__AdminEmail = 'vault-admin@example.test'
$env:SafeVault__AdminPassword = '<your unique strong password>'
dotnet run --project src/SafeVault --urls https://localhost:7043
```

The admin role is assigned at startup only when those settings are supplied. A member who signs up through the form cannot choose a role or access `/admin`. Remove the password from your environment after the admin account has been created. Use `ConnectionStrings__Vault` to select another SQLite database.

## Security changes and checks

| Vulnerability | Fix | Verification |
| --- | --- | --- |
| Invalid usernames, oversized inputs | Validate username, email, password, and note fields server-side and bound the request body. | Registration rejects markup in the username. |
| SQL injection in user lookup | Use `Database.SqlQuery<string>` with an interpolated parameter and select only the username column. SQLite receives input as data. | An admin's valid lookup succeeds. A lookup containing an apostrophe returns no match without a query error. |
| Stored XSS in notes | HTML-encode the note on output and apply a restrictive content security policy. | A harmless tag renders as text, and a second user cannot read the note. |
| Password disclosure and unauthorized access | Identity hashes passwords and enforces lockout, secure cookies, and role policy. | Wrong passwords fail, anonymous vault requests redirect, and the admin route denies ordinary members. |
| Excessive login requests | Limit login POST requests per client IP in addition to Identity account lockout. | Requests above the limit receive HTTP 429. |
| Cross-site form submissions | Validate an antiforgery token on every POST. | A POST without a token receives HTTP 400. |

```powershell
dotnet test tests/SafeVault.Tests
```

The NUnit suite runs against an isolated SQLite database using ASP.NET Core's test server. The local Release run on .NET 10 passed all eight tests. GitHub Actions is configured to run the same suite on each push.

## How Copilot assisted

GitHub Copilot Chat suggested selecting only `UserName` in a composable parameterized query, using the `Value` alias required for EF Core scalar SQL. It also generated an explicit authenticated Admin policy and a per-IP fixed-window limiter for login. I adapted the snippets to minimal API endpoints and kept role assignment on the server. Copilot reviewed the notes output encoding and suggested testing that harmless markup displays as text. The integration test checks that behavior through the vault page and verifies that another user cannot read the note.

This is a single-instance course demo. For production use, add verified account recovery, managed key storage, audit logging, and a database migration and backup plan. If deploying behind a reverse proxy, configure trusted proxy addresses before using the forwarded client IP for rate limiting.
