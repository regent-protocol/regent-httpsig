# Governance

regent-httpsig is a small library with a small governance model. This file says who decides what, how a contributor becomes a maintainer, and how this file itself changes.

## Roles

**Contributor.** Anyone who opens an issue or a pull request. No agreement to sign beyond the Apache-2.0 licence of the repository; by submitting a change you licence it under the same terms.

**Maintainer.** Has the commit bit, reviews and merges pull requests, cuts releases to PyPI, and answers security reports under SECURITY.md. Maintainers are listed in MAINTAINERS.md with their affiliation.

**Security contact.** The address in SECURITY.md. Today it is the maintainer.

## Decisions

Changes land through pull requests with a green CI run. A pull request needs approval from one maintainer who is not its author; while there is a single maintainer, that maintainer's own changes are held for 48 hours before merge so that anyone can object on the pull request.

Anything that changes the wire behaviour of the library, the set of supported drafts, or a public API is announced in the pull request title with the draft revision it targets, and recorded in CHANGELOG.md.

The library implements external specifications: RFC 9421, the Web Bot Auth drafts, and the AAuth drafts. It does not define its own. Where a draft revision changes behaviour, the library tracks the revision published on the IETF datatracker, not the editor's copy, and the version number in CHANGELOG.md names the revision it targets.

Disagreements are resolved on the pull request. If maintainers cannot agree, the change does not merge.

## Becoming a maintainer

A contributor becomes a maintainer after three merged pull requests of substance over at least sixty days, a nomination by an existing maintainer on a public issue, and no objection from other maintainers within fourteen days. A maintainer from a different organization than the existing maintainers is explicitly welcome; the project's stated goal is at least two maintainers from two organizations.

A maintainer who has not reviewed or merged anything for six months is moved to emeritus in MAINTAINERS.md and can return by asking on an issue.

## Releases

Any maintainer can cut a release. Versions follow semantic versioning; a change of targeted draft revision is at least a minor version. Releases are published to PyPI from CI through trusted publishing; no maintainer holds a long-lived PyPI token.

## Changing this file

Changes to this file follow the same pull request process, with a fourteen-day comment period announced on an issue.
