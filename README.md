# release-check

A conservative local audit before preparing an open-source repository. It reports
privacy, secret, attribution and reproducibility blockers without printing matches.
It never publishes, changes the source repository, or fetches Git history.

Requires Python 3.11+ and Git. The CLI uses only the Python standard library.

## Quickstart

From a local clone, install into a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
release-check --help
```

Print the required files, accepted README headings and manifest shape without a scan:

```sh
release-check --requirements
```

Then supply your **external** denylist and private report destination:

```sh
release-check /path/to/repository --denylist /private/terms.json --reports /private/reports --scrub-plan
release-check /path/to/repository --denylist /private/terms.json --reports /private/reports --verify --export /private/exports/new-copy
```

Alternatively run `python3 release_check.py` directly without installing it.
`RELEASE_CHECK_DENYLIST` and `RELEASE_CHECK_REPORTS` supply the two path defaults.
Explicit `--denylist` and `--reports` flags override these environment variables:

```sh
export RELEASE_CHECK_DENYLIST=/private/terms.json
export RELEASE_CHECK_REPORTS=/private/reports
release-check /path/to/repository
```

With no report override, reports go to `~/.local/state/release-check`.
Missing denylist configuration exits 2 with the exact flags and environment
variables to supply; an empty report default also explains how to set it.
The denylist is mandatory, read only at runtime and never copied to an export.
Keep it outside the repository. Formats: a JSON string array, an object containing
`terms`, an object containing `categories` with lists or `{terms: [...]}`, or one
term per line. Term indices are zero-based, in input order; category order is
JSON insertion order. Matching is case-insensitive. Purely alphabetic terms
(`str.isalpha()`) match whole tokens only: Unicode letters, digits and underscores
are word characters. Synthetic term `cat` blocks in `cat`, `CAT`, `cat-file`,
`cat.txt` and `/cat/`; it does not match `cats`, `bobcat`, `cat_file`, `cat2` or
`catFood`. Terms containing nonletters, such as emails, handles and paths, match
literal strings. Embedded plain words produce no findings or review entries.
Denylist hits and secrets cannot be waived. Report paths and diagnostics remain
conservatively redacted without exposing private terms.

## What is checked

- Working files, including untracked/ignored files other than known dependency,
  cache and build directories; Git metadata is scanned separately.
- Every commit reachable from local refs and reflogs, its author/committer/message,
  every historical filename and distinct blob/path pair. Shallow history blocks.
- Owner-identifying names, family/agent names, emails, handles, hosts and home
  paths supplied in the external denylist; known-private repository references,
  common key formats, labelled credentials, bearer tokens and credential URLs.
  Random-looking constants and filenames alone are not secrets. Media is listed
  for human review.
- A known SPDX licence in the top-level LICENSE/COPYING file and agreement with
  pyproject.toml or package.json declarations; dependency licence checks after
  installation, excluding the project's own distribution by its declared name.
  Other licence mentions do not identify the project's licence.
- README, limitations, CONTRIBUTING, SECURITY, issue templates, tests and declared
  quickstart, test, lint and type commands. Configured Ruff/mypy checks must be listed.

Pass known-private repositories with repeated `--private-repo owner/name` flags.
The tool never calls a hosting API to infer visibility. Supply this list separately
from the repository; public and private URLs look the same without that evidence.

Every email address blocks unless it uses `example.com`, `example.org` or
`example.net`, a Git noreply domain, or the exact local part `git`, `noreply` or
`no-reply` (case-insensitive). Numeric package versions such as `python@3.11` are
not email addresses. Real home paths under `/home/<name>/` and
`/Users/<name>/` block; the documented placeholders `/home/user/`, `/home/you/`
and `/Users/name/` pass. Put owner identifiers that do not fit these documented
placeholders in the external denylist. Documentation IP addresses
(`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), `/workspace/sample-project`,
protocol constants and GitHub API URLs need no approvals. Denied hosts such as a
synthetic `windows-01` remain detectable as literal strings. Secrets are still
checked everywhere.

## Manifest and verification

`release-check.json` declares export exclusions and commands. `--manifest PATH` can
instead use a private external manifest. `--verify` authorizes those reviewed commands
to run; without it, readiness remains blocked. No commands are inferred or executed
from arbitrary README prose. `argv` avoids shell interpretation.
With `--verify` and no manifest, no commands run. The report blocks with
`quickstart-not-declared`, `test-command-not-declared` and
`verification-not-configured`; provide a manifest with exact commands to proceed.

```json
{
  "exclude": ["deployment/", "local-config/"],
  "quickstart": [
    {"file": "README.md", "line": 16, "argv": ["python", "-m", "pip", "install", "."]},
    {"file": "README.md", "line": 17, "argv": ["release-check", "--help"]}
  ],
  "checks": [
    {"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}
  ],
  "approvals": []
}
```

Quickstart entries must match the exact command at the declared documentation line.
Verification creates a snapshot of the working files, clones that snapshot into a
fresh directory and creates a fresh venv and HOME without inherited credentials.
The first commands must install the project and any required test tools. Each
quickstart/check command's exit code and output fingerprint are recorded; its raw
output is discarded. Failed venv creation is the exception: reports include a
privacy-redacted diagnostic tail of at most 1000 characters.
`--timeout` bounds each command (default 300 seconds). Pip may contact package indexes.

Approvals acknowledge a specific reviewed media file or dependency license finding:
`scope`, `kind`, `path`, `fingerprint`. They apply to that exact scope/path/value;
they do not match every occurrence globally. Never approve unseen media. Secret
findings cannot be waived. Review approvals as code changes.
By default, approvals live in the audited repository's `release-check.json` and are
the repository author's own statement. Matched approvals stay visible as reviewed
findings in reports and contribute to `reviewed_count`. Use an external manifest
when review statements must come from outside the repository; the tool does not
authenticate the author of an approval.

### Approving findings

Copy the exact `scope`, `kind`, `path` and `fingerprint` from a media or dependency
license finding. Dependency approvals require a human-readable reason. Denylist
and secret findings cannot be accepted; existing approvals for them match nothing
and appear as stale. Never include a private term in a reason.

Dependency licenses are recognized from SPDX expressions, metadata and classifiers.
Common permissive licenses (including generic BSD, MIT, Apache, ISC, Zlib and Python)
and weak copyleft (LGPL, MPL and EPL) are accepted. GPL and AGPL require review.
An OR expression needs an acceptable branch; AND needs every part acceptable.
An OR choice without an acceptable branch retains any GPL/AGPL or proprietary
indication. Invalid expressions retain those indications even when parsing fails.
Unknown SPDX references and exceptions also retain recognizable restrictions.
The generic `License :: OSI Approved` classifier is neutral: it neither blocks a
recognized permissive/weak-copyleft licence nor establishes a licence on its own.
Each metadata field, classifier and shipped license file is checked independently;
a separate GPL/AGPL indication wins over a permissive label or placeholder expression.
Labels must match complete known identifiers/names or a valid expression of them;
mentioning a license inside custom or proprietary wording does not establish acceptance.
A complete grant in a legacy License field is recognized as license-text evidence
before examining GPL references inside canonical LGPL/MPL text.
Unknown free-text metadata, expressions, classifiers and shipped license candidates
require review even beside accepted evidence; only empty fields and documented
placeholders (`UNKNOWN`, `NONE`, `NOASSERTION`, `Dual License`) make no assertion.
Strong-copyleft and proprietary indications still block.
Unknown licenses and unlabelled packages without recognizable license-text evidence
still require review. Recognized labels provide evidence even without a file.
Unlabelled packages need a plain license document containing recognized complete
permissive/weak-copyleft text or a valid SPDX-only declaration. Candidates include
LICENSE/LICENCE, COPYING, COPYRIGHT, UNLICENSE, license identifiers such as
`GPL-3.0.txt`, files under `licenses`/`licences`, and installed `License-File` entries.
NOTICE files are scanned for licence assertions but cannot establish acceptance or
supply digest evidence, even if declared by `License-File` or containing complete
recognizable licence text. They remain protected attribution. Shipped NOTICE
files require explicit dependency review even alongside an accepted licence label; restrictive
assertions remain blockers subject to exact dependency review approvals.
Empty, binary, source, markup and unrecognized/proprietary license files cannot
establish acceptance.
Verification reports file-based acceptance under `accepted_on_license_file`.
Shipped SPDX-only declarations use the same AND/OR rules.
Complete standard Apache, MPL and LGPL texts are recognized before examining
GPL references or ordinary words such as "commercial damages" in their terms.
Recognition checks the whole normalized text against fixed canonical fingerprints;
ordinary copyright headers, case, punctuation and whitespace may vary. Appended
restrictions or unrecognized additional license files still require review.
Copyright-prefix normalization preserves GPL/AGPL and proprietary indications.
License files use UTF-8/16/32 byte-order marks or clear NUL-byte lane patterns
for unmarked UTF-16/32. Unsupported, ambiguous or malformed encodings remain
unknown and blocking; digest evidence cannot resolve them.
A permissive SPDX header cannot hide a separate GPL grant.

Existing `dependency_licenses` entries remain supported: normalized installed package
name keys with exact `version`, `spdx` expression and full `sha256` of an installed
license file. Existing lowercase-name keys also work. This evidence clarifies ambiguous
metadata but cannot erase a detected strong-copyleft or proprietary license.
This includes indications in malformed expressions, classifiers and SPDX headers.
Only a plain license document can supply the digest; NOTICE, code and markup do
not qualify. Empty, corrupt or binary files cannot supply a resolution. Every
unknown shipped file must be covered by the supplied digest; one reviewed document
cannot waive another file's unknown obligations. Evidence that resolves an unknown license leaves a visible
`dependency-license-review` finding with `reviewed: true` and
`review_source: "dependency_licenses"`, counted in `reviewed_count`.

To accept a specific dependency finding after review, add it to the same `approvals`
array used above, with a nonempty `reason`:

```json
{
  "scope": "verification",
  "kind": "dependency-license-review",
  "path": "@dependency/example",
  "fingerprint": "0123456789abcdef",
  "reason": "Reviewed this exact distribution and accepted its obligations."
}
```

Copy the four identifying fields from the report; the example fingerprint is a
placeholder. The fingerprint binds package name, exact version, metadata and all
installed license-file hashes/paths, plus any supplied `dependency_licenses` entry.
Changed versions, files or supplied license evidence invalidate the review.
Reviewed findings remain visible with `reviewed: true` and do not count as blockers.
License obligations and source provenance still need human review.
Text recognition uses a bounded set of canonical texts; uncommon wording,
combined notices and unsupported encodings can still require explicit review.
Oversized or malformed dependency metadata blocks with a coverage finding; size,
file-count and expression-depth limits keep hostile inputs bounded. Coverage
findings cannot be waived by license evidence or approvals.
SPDX size/depth limits also apply to shipped declarations and digest evidence.
Missing file inventories, missing recorded/declared licence files, unrecorded
licence files in installed metadata, malformed headers and ambiguous package
identities also block coverage. Duplicate JSON keys and conflicting package-name
aliases cannot discard earlier gate assertions. Corrupt metadata stays a coverage
failure even beside accepted licence or review evidence.
All recognized root licence files are checked in full, including wording before
the MIT grant. Only MIT headings may be normalized away at the root; declarations
of other licences remain part of the check. Legacy `pyproject.toml` licence tables
must also agree with MIT;
neither a second root licence nor table metadata can silently bypass the check.

After venv creation fails, the tool checks whether the same interpreter can import
`ensurepip` and recognizes missing-support diagnostics across line breaks. The finding
names the Python version and the `python3.<minor>-venv` package on Debian/Ubuntu,
with general install/enable advice for other systems. Other failures keep a different
cause and a bounded error tail with private terms, credentials and absolute paths
redacted. Absolute paths, including spaces or embedded quotes, are removed through
the end of their diagnostic line; ordinary wording such as Debian/Ubuntu on other
lines remains readable.

## Export and reports

`--scrub-plan` lists exact paths to drop, findings to replace/remove by term index or
fingerprint, media to review and the requirement to flatten history. It prints no
replacement source strings. Make content fixes in a source worktree and rerun.

`--export DIR` requires a new directory outside the source and copies the current
working files, without `.git`, generated environments, credential files or manifest
exclusions. It creates exactly one commit with a generic identity, no remote and no
original history. It scans the entire export again, including its new metadata,
licence/quality checks and clean-clone verification. Findings do not silently
rewrite source, licence text or file names.
A blocked export is a **private review artifact**, never a publishable success.

JSON and Markdown reports live in `<report-root>/<repo>/<UTC-timestamp>/` with
0700 directories and 0600 files. They contain counts, check statuses, safe relative
paths, line numbers, term indices, object IDs and one-way SHA-256 fingerprints (first
16 hex characters). Private filenames are replaced with path fingerprints. No
matched content, credentials or denylist terms are included. Quickstart/check
command output is represented only by fingerprints; the bounded, redacted venv
diagnostic tail is included when venv creation fails. The summary
prints only a relative report locator. Exit codes: 0 = audited target ready, 1 =
blockers, 2 = incomplete/error. With an export, exit 0 refers to the export; the
original repository can still have history findings.

## Honest limitations

This is a release gate, not a security or legal guarantee. False positives are
expected. Unrecognized secret formats may escape detection. The tool does not OCR images,
recognize faces, unpack archives, discover nonlocal Git refs or unreachable objects,
or determine hosted repository visibility. History coverage is local refs/reflogs;
fetch any required refs yourself first. Symlinks and submodules block coverage and
are never followed. Git LFS pointers block unscanned external content. Archives and
binary formats require separate human review. Global Git hooks, filters and signing
configuration are disabled for the audit's Git operations.

Fresh HOME/venv is isolation from credentials and caches, **not a security sandbox**.
Only verify repositories and manifest commands you trust; their code can access the
machine and network. Real browser, account, hardware and deployment checks stay
manual. This tool starts no services or timers itself.

## Development

```sh
python3 -m unittest discover -s tests -q
```

Tests use synthetic repositories and a fake external denylist in temporary folders;
they do not load user privacy files or use network services.

### Offline CLI proof

From the clone, keep temporary fixtures in the ignored scratch directory:

```sh
mkdir -p .scratch
export TMPDIR="$PWD/.scratch"
python3 -m unittest discover -s tests -p test_audit_rework.py -k _cli_ -v
```

The command should pass (exit code 0). These tests launch
`python release_check.py ... --verify` as a subprocess against generated fake
repositories. Their quickstart copies bundled fake distribution metadata into the
fresh verification venv; no package download or real dependency is needed.

`test_v3_r2_cli_permissive_weak_and_unlabelled` checks MIT, Apache, BSD, LGPL, MPL,
EPL and an unlabelled package with the bundled MIT license text. Each actual audit
must exit **0**, report `ready: true`, zero blocked dependencies and no findings.
The unlabelled case must also appear in `accepted_on_license_file`.
Control cases for GPL, AGPL and an unlabelled package without license evidence
must exit **1** and report `ready: false`; those are expected blockers, so the
test command still exits 0.

The same command proves these bypasses remain blocked. Each actual audit
must exit **1** and report `ready: false`; the tests pass only when it does:

- `test_finding_1_cli_placeholder_cannot_report_ready`: NOASSERTION cannot hide GPL.
- `test_finding_2_cli_proprietary_label_blocks`: mentioning MPL in proprietary
  wording cannot establish acceptance.
- `test_finding_3_cli_empty_and_proprietary_files_block`: empty or proprietary
  license files cannot qualify an unlabelled package.
- `test_finding_4_cli_wide_gpl_and_misleading_header_block`: UTF-16 GPL text and
  a GPL grant after an MIT SPDX header still block.
- `test_final_gate_cli_parser_failures_cannot_be_digest_waived`: digest evidence
  cannot erase GPL/AGPL or proprietary indications after strict parsing fails.
- `test_final_gate_cli_missing_files_and_unbound_unknown_block`: missing inventory,
  missing/unrecorded licence files, malformed headers, duplicate identity fields
  and a second unknown document cannot be waived by another file's digest.

`test_final_gate_cli_generic_classifier_is_neutral` proves MIT, Apache, BSD and
LGPL remain ready alongside the generic OSI classifier.

`test_notice_cli_cannot_accept_unlabelled_package_or_erase_restrictions` proves
NOTICE alone cannot qualify an unlabelled package, and its restrictive assertions
remain visible blockers.

It also checks standard Apache/MPL/LGPL texts, restrictive legacy fields, a second
unknown license candidate, classifier recognition, bound review evidence and
malformed metadata. Complete standard texts are bundled under `tests/fixtures/licenses`
with their original notices, so the proof does not depend on host-installed files.

## Disposable audit fixtures

For command-proof runners that cannot retain shell activation, use explicit venv
paths after `python3 -m venv .venv`: `.venv/bin/python -m pip install .` and
`.venv/bin/release-check --help`. The Quickstart activation form remains supported.

A synthetic audit project needs a complete recognized license, not just the word
MIT. Copy this project's complete MIT `LICENSE` into the fixture; retain its grant
and attribution. Add `README.md` with a Limitations heading, `CONTRIBUTING.md`,
`SECURITY.md`, an issue template under `.github/ISSUE_TEMPLATE/` and a real test
under `tests/`. Declare exact README command lines and test commands in the
fixture's `release-check.json`. Keep a synthetic denylist outside the fixture Git
root, and export outside that root. A dependency-free fixture can declare
`python --version` as its quickstart and a standard-library unittest as its check.
Commit it with an example-domain Git identity. With all required files present,
`--verify --export` should report ready true and zero findings. A single MIT label
without its grant correctly blocks; an export alone does not prove readiness.
