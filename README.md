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
With no report override, reports go to `~/.local/state/release-check`.
The denylist is mandatory, read only at runtime and never copied to an export.
Keep it outside the repository. Formats: a JSON string array, an object containing
`terms`, an object containing `categories` with lists or `{terms: [...]}`, or one
term per line. Term indices are zero-based, in input order; category order is
JSON insertion order. Matching stays case-insensitive and literal. Purely alphabetic
terms use Unicode letters (`str.isalpha()`): a whole word or separate component
blocks, while a hit confined to one longer letter component is reviewable.
Digits, punctuation, straight/curly apostrophes, underscores, hyphens, dots, slashes
and `@` delimit components, so terms in snake_case identifiers, filenames, paths,
URLs, email addresses and hyphenated words still block when separate components.
CamelCase splits at lowercase-to-uppercase transitions and before an uppercase
letter followed by lowercase after an uppercase letter (`HTTPServer` splits into
`HTTP` and `Server`). Whole components and hits crossing these transitions block;
hits starting at an ambiguous uppercase-acronym/lowercase join also block
(`HTTPcat` might mean `HTTP` plus `cat`).
Substrings within a longer component are reviewable. Combining marks, invisible
format characters or decoding replacements beside a hit stay blocking because
their boundaries are uncertain. All-uppercase or all-lowercase
letter runs have no case transitions. Thus synthetic term `cat` blocks in `cat`,
`cat's`, `cat_file`, `cat-file`, `cat.txt`, `/cat/`, `cat [at] example.com`, `catFood`
and `HTTPcat`, but is reviewable in `cats`, `bobcat`, `scatter` and `SCATTER`.
Terms containing any nonletter keep their existing substring rule, including the
existing ASCII-alphanumeric boundaries for alphanumeric aliases of at most three
characters. Denylist findings can be accepted only by an exact owner approval.

Reports list embedded alphabetic hits separately in `reviewable_findings`, with
`reviewable_count` and a nonblocking Markdown section. They retain safe file paths,
line numbers, term indices and fingerprints, without matched terms or surrounding
text. They do not count as blockers or as approved (`reviewed_count`) findings,
do not require scrub replacements, and cannot change the exit status on their own.
Filename redaction and venv diagnostic redaction still cover every substring.

## What is checked

- Working files, including untracked/ignored files other than known dependency,
  cache and build directories; Git metadata is scanned separately.
- Every commit reachable from local refs and reflogs, its author/committer/message,
  every historical filename and distinct blob/path pair. Shallow history blocks.
- Denylist terms, email/phone/IP addresses, tailnet and internal hostnames, home
  paths, known-private repository references, credential files, common key formats,
  labelled credentials and high-entropy strings. Media is listed for human review.
- Standard MIT license wording and metadata consistency; dependency metadata and
  license-file evidence after installation. Dependency-free `package.json` projects
  are accepted under the restrictions below. Other root licenses and dependency
  ecosystems require manual review. NOTICE, UPSTREAM and license files are protected.
- README, limitations, CONTRIBUTING, SECURITY, issue templates, tests and declared
  quickstart, test, lint and type commands. Configured Ruff/mypy checks must be listed.

Pass known-private repositories with repeated `--private-repo owner/name` flags.
The tool never calls a hosting API to infer visibility. Supply this list separately
from the repository; public and private URLs look the same without that evidence.

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

For non-Python commands, optionally add `"verify_tools": ["node"]` to the manifest.
The list accepts at most eight distinct bare executable names matching
`^[A-Za-z0-9._+-]+$`, excluding `.` and `..`; paths and command arguments are invalid.
Only absolute entries on the caller's PATH are searched; empty and relative entries
are ignored. Each tool and its resolved symlink target must be outside the audited
repository, original source tree, report directory and export directory. Its target
must be an absolute regular executable file. Accepted tools are symlinked into the
isolated venv bin directory before commands run. A missing, unsafe, non-executable
or conflicting tool blocks verification with `verify-tool-missing`.
The caller's PATH is not inherited; the existing system PATH suffix and isolated
HOME, XDG directories and TMPDIR remain in effect. Declare supporting tools separately
when a tool needs other executables outside the system PATH.

Every `package.json` anywhere in the audited tree, excluding `.git`, is checked
independently. A manifest avoids dependency-ecosystem manual review only when it is
a valid JSON object of at most 4 MiB with no duplicate keys, no nonempty
`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`,
`bundledDependencies`, `bundleDependencies`, `workspaces`, `overrides` or `resolutions`,
and no lifecycle script keys named `install`, `prepare`, `publish` or `dependencies`,
or starting with `pre` or `post` (including empty commands). Scripts must be an
object of string commands. Any legacy `licenses` key, truthy `gypfile` or
`binding.gyp` anywhere in the tree requires manual review. There must be no lockfile
or `node_modules` anywhere in the tree or tracked paths. Recognized lockfiles are
`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`
and `bun.lockb`. Invalid or oversized metadata and symlinked manifests remain for
manual review. A present `license` must be a string equal to the detected licence
identifier; discrepancies produce `license-metadata-mismatch`. Nested findings name
the manifest's relative path. Other ecosystem filenames keep requiring manual review.

Approvals acknowledge a specific non-secret false positive or reviewed media file:
`scope`, `kind`, `path`, `fingerprint`. They apply to that exact scope/path/value;
they do not match every occurrence globally. Never approve unseen media. Secret
findings cannot be waived. Review approvals as code changes.
By default, approvals live in the audited repository's `release-check.json` and are
the repository author's own statement. Matched approvals stay visible as reviewed
findings in reports and contribute to `reviewed_count`. Use an external manifest
when review statements must come from outside the repository; the tool does not
authenticate the author of an approval.

### Approving findings

Copy the exact `scope`, `kind`, `path` and `fingerprint` from a finding. Add a
human-readable `reason` for denylist approvals. This supports verified public data,
such as a public IRS record; accepted findings stay visible in reports, and
approvals that match nothing are listed as stale. Never include the private term
in the reason.

```json
{"scope":"tree","kind":"denylist","path":"public-data.csv","fingerprint":"0123456789abcdef","reason":"Verified this exact public IRS record."}
```

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
license/quality checks and clean-clone verification. Missing historical attribution
blocks it. Findings do not silently rewrite source, license text or file names.
A blocked export is a **private review artifact**, never a publishable success.

JSON and Markdown reports live in `<report-root>/<repo>/<UTC-timestamp>/` with
0700 directories and 0600 files. They contain counts, check statuses, safe relative
paths, line numbers, term indices, object IDs and one-way SHA-256 fingerprints (first
16 hex characters). Private filenames are replaced with path fingerprints. No
matched content, credentials or denylist terms are included. Quickstart/check
command output is represented only by fingerprints; the bounded, redacted venv
diagnostic tail is included when venv creation fails. The summary
prints only a relative report locator. Exit codes: 0 = PASS, 1 = FAIL, 2 = INCOMPLETE.
With an export, the exit code follows the export outcome; the original repository
can still have history findings.

## Outcome and export receipt

Every audit report, including the export report, has an `outcome` (`PASS`, `FAIL`
or `INCOMPLETE`) and sorted machine-readable `reasons`. The older `ready` field is
deprecated and remains for compatibility; it is true only when the outcome is
`PASS`. PASS requires no unresolved findings, passed verification, accepted license
and verified dependency status, plus at least one accounted tree file and commit.
Unknown or missing coverage or verification evidence produces INCOMPLETE, including
verification that was not run, unavailable tools, unsupported files, pending
media review and missing license or dependency evidence. A change to the export while
it is being audited is FAIL (`candidate-mutated`). Known violations such as leaks, denylist hits,
failed commands, README commands that contradict the manifest, and missing
attribution produce FAIL. FAIL takes precedence over INCOMPLETE, while reasons for
both remain in the report. The stdout summary includes `outcome`; with `--export`
it also includes `export_outcome`. The process exit code follows that export
outcome. In particular, verification-not-run, missing verification tools and
unsupported coverage now exit 2 when no known violation makes the outcome FAIL.

When `--export` is used, `receipt.json` is written beside `report.json` in the
reports directory, never inside the export. A reports directory inside the export
is refused. The receipt binds the export inventory (every path including empty
directories, full permission bits, file bytes, symlink targets without following
links, the export's `.git` files other than the index, refs and HEAD), manifest recipe,
policy (denylist and private-repository list digests, default exclusions, verify
flag and timeout), and scanner (release-check version and implementation digest,
Python version and Git version). It also records export HEAD and tree identifiers
and a `receipt_sha256`. It contains no denylist terms or private repository names.

Validate a receipt without running an audit or verification:

```sh
release-check --validate-receipt /private/reports/.../receipt.json /path/to/export \
  --denylist /private/terms.json --verify
```

Pass the same `--manifest`, `--private-repo` and `--timeout` options used for the
audit when applicable. An unchanged PASS receipt exits 0. Changes to export bytes,
modes, paths, refs, untracked files, recipe, policy flags or scanner produce
INCOMPLETE with reason `receipt-stale` and a `mismatched` list. An unparseable,
tampered, duplicate-key or unknown-schema receipt produces INCOMPLETE with reason
`receipt-invalid`. A receipt created for a FAIL or INCOMPLETE export preserves that
outcome if its bindings still match.

The receipt is a hash binding, not a signature: it does not authenticate who wrote
it. Keep it outside the export and read it from the trusted job record. No dedicated
external secret scanners are involved yet. PASS means only that the declared checks
passed on that export.

## Honest limitations

This is a release gate, not a security or legal guarantee. False positives are
expected. Entropy cannot identify every secret. The tool does not OCR images,
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
must exit **0**, report `outcome: PASS` (`ready: true` for compatibility), zero blocked dependencies and no findings.
The unlabelled case must also appear in `accepted_on_license_file`.
Control cases for GPL, AGPL and an unlabelled package without license evidence
must exit **1** and report `outcome: FAIL` (`ready: false` for compatibility); those are expected blockers, so the
test command still exits 0.

The same command proves these bypasses remain blocked. Each actual audit
must exit **1** and report `outcome: FAIL` (`ready: false` for compatibility); the tests pass only when it does:

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
LGPL can pass alongside the generic OSI classifier.

`test_notice_cli_cannot_accept_unlabelled_package_or_erase_restrictions` proves
NOTICE alone cannot qualify an unlabelled package, and its restrictive assertions
remain visible blockers.

It also checks standard Apache/MPL/LGPL texts, restrictive legacy fields, a second
unknown license candidate, classifier recognition, bound review evidence and
malformed metadata. Complete standard texts are bundled under `tests/fixtures/licenses`
with their original notices, so the proof does not depend on host-installed files.
