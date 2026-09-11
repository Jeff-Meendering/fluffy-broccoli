# Security policy

## Supported versions

Only the most recent pilot build receives fixes. 0.3.0 is the current version;
earlier builds are unsupported. Verify the version in the application window or
in the packaged `README.md` before reporting.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.** Use a
private report instead:

1. Open <https://github.com/Jeff-Meendering/fluffy-broccoli/security/advisories/new>
   and submit a private security advisory, or
2. Use the "Report a vulnerability" button on the repository's Security tab.

Both routes reach the maintainers privately and let us discuss a fix before any
disclosure. If private advisories are unavailable, contact a maintainer through
a private channel rather than posting details publicly.

Include the version, platform, a minimal reproduction using synthetic data, and
the impact you observed. Never attach real personal data, real findings or
exported reports; replace values with synthetic examples.

## Scope

Reportable issues include, for example:

- Parser, archive, OCR or model input handling that crashes, hangs or escapes
  the configured file, output, timeout or memory limits when scanning a
  hostile file.
- Sensitive data left in temporary directories, logs, exports or crash dumps.
- Findings or report exports that expose more personal data than the UI
  indicates, or privacy controls that can be bypassed.
- Dependency vulnerabilities in the pinned NuGet, Java, OCR or model assets.

Not reportable here: detection misses, false positives or accuracy limits.
Those are normal engineering work; see `REVIEW.md` and open a normal issue.
Analyst case data and exported findings must never be included in a report.

## Response expectations

We aim to acknowledge a private report within seven days and to agree a
disclosure timeline with the reporter. This is a pilot project maintained on a
best-effort basis; there is no bounty program and no guaranteed fix date.
