# CodeCook

CodeCook is a privacy-first, browser-local source-code pattern scanner. It checks supported source files for selected risky patterns, explains each match, shows CWE references and remediation guidance, and exports a JSON report.

## What works

- Upload multiple supported source files (`.c`, `.cpp`, `.cs`, `.css`, `.go`, `.html`, `.java`, `.js`, `.jsx`, `.json`, `.kt`, `.php`, `.py`, `.rb`, `.rs`, `.sh`, `.sql`, `.ts`, `.tsx`, `.xml`, `.yaml`, `.yml`, `.env`, `.toml`, `.ini`). Files must be under 1 MB each; up to 30 files are read per selection.
- Paste code directly or load the sample.
- Run local static pattern checks for credential-like strings, possible SQL injection, shell command construction, dynamic evaluation, unsafe HTML insertion, disabled TLS verification, unsafe pickle deserialization, weak password hashing, risky randomness, permissive CORS, debug mode and HTTP URLs.
- Filter findings by severity, inspect line context, copy remediation guidance, and export a JSON report.
- No sign-in or API key required. Files are read in the browser and are not uploaded by the scanner. The site does not execute submitted code.

## Important limitations

This is an MVP static pattern scanner, not Semgrep, Gitleaks, an AI security auditor, or a complete SAST engine. It can miss vulnerabilities and report false positives. Findings should be reviewed by a developer. It currently scans individual files, not ZIP archives or full repository dependency graphs. No automated patch is applied; the tool provides remediation guidance.

## Run locally

This repository is a TanStack Start / React application configured for the hosting platform. Use the repository's package manager and lockfile in an environment with the project toolchain installed. Typical scripts are `bun run dev`, `bun run typecheck`, and `bun run build` from `app/`.


## Suspicious link checker

The **Spam link check** mode accepts one URL per line and performs local heuristic checks for malformed URLs, embedded credentials, Punycode domains, raw IP hosts, known URL shorteners, higher-risk TLDs, phishing-style wording, redirect parameters, unusually long URLs, deep subdomain chains, plain HTTP, and encoded URL characters. It does not open links, make network requests, or query a live reputation/threat-intelligence database. Results are warning signals, not a definitive spam verdict; legitimate URLs can trigger warnings and malicious URLs can evade these checks.

## Local verification

The link-checker tests live in `tests/spam-link-checker.test.ts`. Run `bun test tests/spam-link-checker.test.ts` in the project environment.


## Source scanning: files, folders, and ZIP archives

- **Files:** select multiple supported source/config files.
- **Folder:** choose a project folder; browser-supported directory upload preserves relative paths such as `src/auth/login.ts`.
- **ZIP:** choose a standard (non-ZIP64, unencrypted) `.zip` archive. It is extracted in the browser using `fflate`; the source is not sent to a server.
- **Limits:** maximum 100 loaded source files per batch, 1 MB per source file, 20 MB total source/expanded archive content, and 500 ZIP entries. ZIP paths containing absolute paths or `..` traversal segments are rejected.
- **Diagnostics:** unsupported extensions, oversize files, malformed/encrypted archives, and other import problems appear in **Upload diagnostics** with the path/name and reason. These upload errors do not have a source line, so they display `Line N/A`. Security findings show the relative file path, exact line number, flagged code, reason, and recommended fix.
- **Detection limitation:** this is a local rule-based pattern scanner, not a full compiler, parser, or data-flow engine. It reports matching risk patterns; it does not automatically diagnose every build/runtime error.
