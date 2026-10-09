# Changelog

All notable changes are recorded here, following Keep a Changelog.

## Unreleased (v0.2.1)

- Recognize additional permissive SPDX identifiers and their expressions.
- Report version-bound, owner-reviewed upstream license dispositions for packages
  without installed license files. Secret approvals and export digest coverage remain unchanged.

## 0.2.0 - 2026-10-08

### Added

- Clear verdicts and readable terminal and Markdown reports.
- A scrub plan with actors, counts and fix text for every finding kind.
- Automatic and manual tests to finish before publishing.
- An export digest and `--check-digest` to detect later changes.
- `--json` for the legacy summary and an example private terms file.
- Specific error codes with safe help sentences.

### Changed

- Default terminal output is readable text.
- Exports contain tracked files only, with a UTC commit date.
- A missing README no longer aborts `--verify`; it produces a finding.

### Removed

- One tool-specific default exclusion unrelated to repository auditing.

## 0.1.0

Initial audit, export and verification.
