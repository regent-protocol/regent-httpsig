# Contributing

Issues and pull requests are welcome. A few things make review faster.

- Say which specification and revision a change targets: RFC 9421, a Web Bot Auth draft revision, or an AAuth draft revision. The library tracks revisions published on the IETF datatracker.
- Add or update a test for any wire-level change: a known-good signature or a request that must fail, next to the existing tests under `tests/`.
- Keep the dependency tree as it is unless the change needs a new one; say why in the pull request.
- Run `ruff check` and the test suite before opening the pull request; CI runs both.
- Security problems go to the address in SECURITY.md, not to a public issue.

Interoperability reports are as useful as code: if the library fails against a real signer or verifier, an issue with the raw request and the expected result is a contribution.
