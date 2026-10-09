# Security Policy

SecretSweep is a local repository scanner that may inspect files containing sensitive information. The tool is designed to avoid exposing secrets, but security issues should still be reported carefully.

---

## Supported Versions

Security fixes are handled for the latest release and the current `main` branch.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` branch | Yes |
| Older versions | No |

---

## Reporting a Vulnerability

Please do not open a public issue with exploit details or sensitive information.

Use GitHub private vulnerability reporting if available. If it is not available, open a public issue asking for a private contact method without sharing technical exploit details.

When reporting, include:

- A short summary
- Affected command or module
- Steps to reproduce safely
- Impact
- Suggested fix if available

Do not include real secrets, private keys, tokens, passwords, or private repository content.

---

## Security Expectations

SecretSweep should:

- Never upload repository contents
- Never execute scanned project code
- Never print full secrets
- Mask detected values in reports
- Avoid writing outside the requested project path
- Handle unusual file names safely
- Keep dependencies minimal
- Fail safely with clear messages

---

## If a Real Secret Is Found

If SecretSweep finds a real leaked secret:

1. Remove it from the project.
2. Rotate or revoke the credential.
3. Check whether it was committed to Git history.
4. Remove it from history if needed.
5. Add proper `.gitignore` rules.
6. Use `.env.example` for safe example values.

---

## Scope

Security scope includes:

- CLI behavior
- File scanning
- Secret masking
- Report generation
- Config loading
- Output writing
- Path handling

Vulnerabilities inside repositories scanned by SecretSweep should be reported to those projects instead.
