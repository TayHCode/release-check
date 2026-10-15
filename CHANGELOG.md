# Changelog

## 0.5.0 — 2026-10-15

Compared with public 0.4.0:

- Replace private-looking examples and fixture identifiers with neutral documentation
  values; construct detector-negative samples at runtime and review only exact
  scanner self-matches through manifest approvals.
- Confine the receipt mutation regression to its explicit temporary candidate.

- Add PASS/FAIL/INCOMPLETE outcomes and sorted reason codes to reports and stdout;
  retain `ready` as a deprecated PASS compatibility field and use outcome-based
  exit codes.
- Write an external `receipt.json` for exports, binding the inventory, recipe,
  policy and scanner; add read-only `--validate-receipt` with stale/invalid receipt
  reporting and document its hash-only trust limits.
- Ignore relative and empty verification PATH entries; reject executable paths and
  symlink targets inside the audited repository, original source, reports or export.
  Preserve these exclusions through export verification and block bin-directory escapes.
- Check every `package.json` outside `.git`, including nested and symlinked manifests.
  Require review for legacy `licenses`, all `pre`/`post` script keys and lifecycle
  hooks, `gypfile` and any `binding.gyp`; retain bounded, duplicate-free JSON checks.
- Accept dependency-free `package.json` projects only with bounded, duplicate-free
  JSON, no dependency declarations, install lifecycle commands, root or tracked
  lockfiles or `node_modules`; check declared licences against the root licence.
- Add manifest `verify_tools` to resolve up to eight declared executables on the
  caller's PATH and link them into the isolated verification bin directory. Missing
  or conflicting tools block verification without inheriting the caller's environment.
- Incomplete runs now exit 2; known failures exit 1 and PASS exits 0.

## 0.4.0 — 2026-10-14

Compared with public 0.3.0:

- Add whole-token alphabetic denylist matching, `--requirements`, clearer external
  configuration and venv diagnostics, and stricter dependency metadata/license
  checks with broader permissive and weak-copyleft recognition and UTF-16/32 text.
- Ignore SSH `git` and automated `noreply`/`no-reply` email local parts and GitHub
  users.noreply addresses. Keep personal-looking emails and real secret signatures
  blocking; construct fake secret test values at runtime without test-path waivers.
- Document valid disposable audit fixtures and explicit venv executable commands.
- Remove readable terminal reports (stdout is JSON), the guided verdict/plan/
  pre-publication checklist from terminal and Markdown reports, `--json`,
  `--check-digest`, export digest/audit integrity records and `--verify-no-venv`.
- Remove blocked-export quarantine/rename behavior, tracked-only exports,
  upstream license dispositions, historical attribution preservation checks and
  Apache NOTICE/provenance enforcement. Exports can exist even with blockers.
- Remove generic phone/IP/hostname and random-string/credential-filename
  heuristics, embedded-word reviews and denylist/secret waivers. Email and home
  detectors retain documented placeholder exceptions; owner terms stay external.
- Remove provider-token, webhook URL, password-hash, pgpass/netrc, prose-secret,
  context-secret, Basic/curl authentication and CLI/XML secret detector families. Narrow assigned-secret labels and
  credential-URL schemes; reduce default sensitive-file export exclusions.
  The remaining signatures do not provide public 0.3.0's full detection coverage.
- Remove the public early unsupported-Python diagnostic, bundled example denylist,
  MANIFEST.in and several prior regression suites; replace the audit/license suites.
  Change the LICENSE copyright line from TayHCode to Release Check contributors;
  retain the complete MIT grant. These removals are listed for owner review, not
  restored in this release.

Further changes included in this release:

- Match alphabetic denylist terms only as case-insensitive whole tokens; match
  terms containing nonletters as literal strings. Remove camel-case/component
  heuristics, embedded-word reviews and denylist approval waivers.
- Replace the public generic email/home-path rules with documented placeholder
  exceptions; remove phone, IP and hostname findings. Owner identifiers also
  come from the external denylist. Placeholders, constants and co-author metadata
  need no approvals or identity-allowance option. Remove random-string and
  credential-filename heuristics; key/token signatures and credential checks remain.
- Explain missing privacy configuration with exact flags and environment defaults;
  document that explicit flags override RELEASE_CHECK_DENYLIST/RELEASE_CHECK_REPORTS.
- Add a documented offline subprocess CLI proof for permissive, weak-copyleft and
  unlabelled dependency acceptance, with expected blockers and four audit bypasses.
- Preserve GPL/AGPL indications across independent metadata fields, classifiers and
  shipped license files, including placeholder expressions and conflicting labels.
- Match entire license labels and expression atoms, including WITH branches;
  incidental permissive or weak-copyleft names never establish acceptance.
- Restore permissive classifier and complete-license-text fallback for unrecognized
  free-text metadata while retaining strong-copyleft/proprietary blockers.
- Keep dependency-license evidence resolutions visible as reviewed findings;
  bind the digest to a plain license document and never erase contrary package text.
- Accept recognized permissive and weak-copyleft dependency licenses, with proper
  SPDX AND/OR evaluation; keep unavoidable GPL/AGPL and unknown licenses for review.
- Decode UTF-16/32 license files and inspect the whole text; a permissive SPDX
  header or reference wording cannot conceal a separate GPL/AGPL grant.
- Accept unlabelled packages only with recognizable permissive/weak-copyleft text
  in shipped license documents, and record file-based acceptance in verification reports.
  Block empty, binary, code, markup and unrecognized/proprietary evidence. Evaluate
  shipped SPDX declarations and distinguish LGPL text from its GPL references.
- Support dependency findings in existing approvals with a required reason and
  fingerprints binding exact package, version, metadata, installed license files and
  supplied dependency-license evidence. File detection uses actual license names or
  License-File declarations, rather than substrings in package paths.
- Add `--requirements` to list enforced files, README headings and manifest shape.
- Bound collected dependency data and report invalid metadata as an unwaivable
  coverage failure; clarify example manifests, repository-authored approvals and
  verification without a manifest.
- Detect missing venv support from wrapped ensurepip diagnostics and a same-interpreter
  import probe, with versioned installation advice in the finding itself. Keep a
  different cause and privacy-redacted error tail for other failures, preserving
  ordinary slash-separated wording such as Debian/Ubuntu.
- Redact entire absolute-path diagnostic suffixes, including spaces and embedded
  quotes, and document the bounded venv-output exception in JSON/Markdown reports.
