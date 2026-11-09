# Security policy

vibeprobe is a security tool, so bugs in its safety rules matter as much as bugs in its checks.

## What counts as a vulnerability

- Any way to make vibeprobe send a request outside its scope (another host, an internal IP, a cloud metadata address), for example through redirects, DNS tricks, IPv6 forms or URL parsing quirks.
- Any way to make it send a method other than `GET`, `HEAD` or `OPTIONS` without `--active`.
- Secrets or personal data written to a report without masking.
- Any network traffic to a destination other than the scan target.

## How to report

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security tab → Report a vulnerability** on <https://github.com/januarsyah901/vibeprobe/security/advisories/new>.

Include the vibeprobe version, the command you ran, and what happened. You will get a reply within 7 days. Once a fix is released you will be credited in the advisory unless you ask not to be.

## Supported versions

Only the latest release receives security fixes while the project is below 1.0.
