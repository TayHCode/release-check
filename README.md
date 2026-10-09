# release-check

A local tool that audits a private Git repository and prepares a one-commit export.
It reports blockers and fixes without printing the text it matched.
It never publishes or changes your source repository.

## What this does not do

This is **not a complete secret scanner**. Encoded, split or obfuscated secrets
and personal data, and unlisted names, are not reliably found. Some common obfuscations are
normalised, but many others remain undetected. Run a dedicated secret scanner too
and read the export yourself before publishing. PASS means the declared checks
passed and no detected finding blocks the target; it is not publication approval.

## Who this is for

Individual developers with many small private repositories, often built with
coding agents such as Claude Code or Codex, who want to open-source some of them
safely. Requires Python 3.11+ and Git; the tool uses only the standard library.

## What you get

A readable audit, a scrub plan and a list of tests to finish before publishing.
An illustrative excerpt with invented data and omitted plan and test steps.
The document locations and report folder below are invented examples:

```text
release-check 0.2.0

VERDICT: FIX-THESE
Judged: the source repository
Blocking: 1   Warnings: 0
Scanned: 8 working files, 2 commits

BLOCKING - fix these, then run again
1. documentation and tests (1)
   missing-document   README.md   tree   id e3b0c44298fc1c14
   Fix: Create this file. A README says what the tool does, how to install it, one usage example and its limitations.

WARNINGS - reported, not blocking
   none

PLAN
 1. [tool, done] Read the working files and all 2 commits of local history. Change nothing in the repository.
 2. [tool, planned] Discard all history. The export gets one new commit. This removes 0 findings that exist only in old commits, author names or commit messages.
 3. [you, needed] Fix 1 license, documentation, test or coverage items listed under BLOCKING.

TEST BEFORE PUBLISHING
 1. [passed] Quickstart step 1 (GUIDE.md line 5) works in a clean clone.
 2. [to do] Clone the export into an empty folder, ideally on another machine or user account, and follow the README from its first line. Nothing may depend on files, tools or logins only you have.

REPORT: sample/example-run/report.md and report.json, under your reports folder
```

## Quickstart

Download or clone this repository. **Python 3.11 or newer and Git are required**:
`tomllib` is part of Python's standard library starting in 3.11. No runtime
packages, virtual environment or installation are needed to run the script.

On Linux or macOS, start here:

```sh
python3 --version
python3 release_check.py --help
```

On macOS, the system `python3` may be 3.9. Get a newer Python from
[python.org](https://www.python.org/downloads/macos/), Homebrew
(`brew install python@3.11`), or uv. With Homebrew, use `python3.11` in place of
`python3` throughout this README. With uv, run
`uv run --no-project --python 3.11 python release_check.py --help`;
replace `--help` with your audit arguments. These options can also supply a
Python with working venv support for `--verify`.

On Windows, use PowerShell and the Python launcher:

```powershell
py -3 --version
py -3 release_check.py --help
```

If the selected Python is older than 3.11, install a newer version from
[python.org](https://www.python.org/downloads/windows/) or run
`winget install --exact --id Python.Python.3.11`. After installing 3.11, select it
with `py -3.11 release_check.py --help`. Windows may map `python3` to a Microsoft
Store shortcut; use `py -3` (or `py -3.11`) in place of `python3` in the examples.

### Optional installed command

For an installed `release-check` command, use a venv or `pipx install .`.
On Linux or macOS with a supported Python:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
release-check --help
```

In Windows PowerShell, the equivalent is:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
release-check --help
```

If PowerShell's policy prevents activation, invoke `.\.venv\Scripts\python.exe`
and `.\.venv\Scripts\release-check.exe` directly; activation is optional.
A working venv with pip is needed for the optional package install and `--verify`.
On Debian/Ubuntu, a missing `ensurepip` usually means the matching `python3-venv`
package (or a versioned package such as `python3.11-venv`) is absent. Ask your
administrator to install it, or use a supported Python from python.org or uv.
Audits and exports without `--verify` still work through the direct script.
The build backend requires `setuptools>=77`; a fresh install may need package-index
access even though the tool has no runtime dependencies. Offline, use the direct
Python command for audits without verification. In the examples below, replace
`release-check` with `python3 release_check.py` if you use the direct script,
or `py -3 release_check.py` in PowerShell.
Prepare the private terms file below before your first audit.

## Your private terms file

Keep this file outside every repository you audit: it contains the very names and
identifiers you want to keep private. Copy `examples/denylist.example.json` to a
private place and replace every placeholder with your own terms. Never commit it.

The four supported formats are:

- A JSON array of strings.
- A JSON object with a `terms` array.
- A JSON object with `categories`, each containing a list or an object with a
  `terms` array, as in the example file.
- One term per line; blank lines and lines beginning with `#` are ignored.

Matching is case-insensitive after NFKC Unicode normalisation and removal of
zero-width formatting characters. Spaces, underscores and hyphens between a
term's word parts are interchangeable, including a joined camelCase spelling
and a line break. Terms of up to three letters or digits match as
whole words; longer terms match anywhere. Term indices are zero-based, in input
order; categories follow JSON insertion order.

JSON objects may also contain an optional `internal_domains` array of domain
names. Hosts at or below these domains are reported as internal hosts. Keep your
own domains in this private file; they never appear as matched text in reports.
For example, use `{"terms": ["invented-person"], "internal_domains": ["example.org"]}`
with invented values when experimenting. Newline lists and JSON arrays contain
terms only. Bare host names require manual review.

Use `--denylist FILE` each time, or set a default once for many repositories:

```sh
export RELEASE_CHECK_DENYLIST=/private/terms.json
export RELEASE_CHECK_REPORTS=/private/reports
```

In PowerShell, use your private paths:

```powershell
$env:RELEASE_CHECK_DENYLIST = 'C:\private\terms.json'
$env:RELEASE_CHECK_REPORTS = 'C:\private\reports'
```

Without a reports override, reports go to `~/.local/state/release-check`.
The terms file is mandatory for auditing and is never copied into an export.

## The three steps

Before aiming for PASS, your repository needs:

- `LICENSE` with the standard MIT text and the correct copyright holder;
  declared license metadata must agree. Other licenses need manual review and
  do not pass this tool's MIT policy automatically.
- `README.md` describing setup and use, with a heading containing
  `limitations`, `known issues` or `where it fails`.
- `CONTRIBUTING.md` for development, tests and contribution instructions, and
  `SECURITY.md` for supported versions and private vulnerability reporting.
- At least one `.md`, `.yml` or `.yaml` issue template under
  `.github/ISSUE_TEMPLATE`, and a `test*.py` file under `tests`.
- `release-check.json` declaring an exact README quickstart and a check with
  `role: tests`. Also declare lint/type checks when Ruff/mypy is configured.

The document checks test presence and the limitations heading; they do not
judge the completeness of contribution instructions or validate issue forms.

1. Audit: `release-check REPO`.
2. Fix every item under BLOCKING, then run the audit again. Keep the source private.
3. Build and verify an export: `release-check REPO --verify --export NEW_DIR`.

Replace `REPO` with the repository root and `NEW_DIR` with a new path outside it.
Then finish the test list and publish the export folder by hand.

## Reading the verdict

- **PASS**, exit 0: declared checks passed and no detected finding blocks the
  judged target. Finish the manual test list, run a dedicated secret scanner and
  read the export yourself. Unlisted names and unsupported secret encodings can
  still be present.
- **FIX-THESE**, exit 1: blockers remain. Each group lists locations and fixed
  instructions for resolving them. Each distinct fix appears once per group;
  history guidance and working-file fixes use separate lines.
- **INCOMPLETE**, exit 2: the audit stopped early. The reason code and help sentence
  explain the next step; this does not establish readiness. Audit exceptions use
  a fixed error response without exception text or a traceback. If writing a report
  also fails, the CLI still reports INCOMPLETE but a complete report may be absent.

Every unreviewed finding in the judged target blocks. A warning is either an exact
finding you acknowledged in the manifest, or a finding found only in the private
source when the export is being judged. Without an export, old-commit findings
still block. The original repository can remain blocked while its export passes.
In particular, a real author or committer email in Git history is expected to
block a source audit. Editing the README cannot remove it. A one-commit export
replaces authorship with a generic identity; keep the original history private
and verify the export. Do not approve a real personal address to silence the gate.

Use `--json` for scripts: the first line retains the `ready`, `counts` and `report`
summary, with `export_ready` and `export_counts` when exporting. In that mode,
`--scrub-plan` adds a second JSON document. The saved reports always include the
verdict, plan and test list. Error JSON includes a fixed `code`, never the argument.
Blocked exports also include `export_warning` in the JSON summary and a warning
in the readable verdict. Each group shows up to ten locations in the terminal;
`report.md` and `report.json` retain every finding.

## The scrub plan

The plan names who acts next: `tool` or `you`. Tool steps are done or planned;
your steps are needed. Verification is done only after it succeeds, including
when no export was requested; blocked verification stays planned. Counts cover six scrub classes: private terms, emails,
IP addresses, internal host names, home paths and credentials.

Discarding history removes old file versions, author identities and commit messages
from the export. Exclusions remove entire files from it. Untracked files stay in
your source folder. The plan lists the tracked exclusions, left-out untracked files,
history counts and findings you must edit or review.

**The tool does not rewrite file contents.** Edit the reported lines yourself,
then re-scan; unresolved content in the export blocks it. License and notice files
are copied unchanged, and missing historical attribution blocks publication.
The plan is always built; `--scrub-plan` remains accepted for existing scripts.

## Test before publishing

Automatic items correspond to each declared quickstart command and check, with
`passed`, `failed` or `not run` taken from its actual execution result. Commands
are identified by position and role; their arguments and output are never printed.
Run with `--verify` to execute them in a clean clone with a fresh HOME and venv.

Manual items always remain `to do`. Repeat the README on another machine or user
account, confirm the license holder and hosting-site fields, and publish the export
as a new repository. Inspect its commit and confirm its digest before publishing.
Revoke credentials even when they existed only in old commits; deletion is not
revocation. Review media and embedded metadata, unreadable content and third-party
licenses when the list calls for them. After publishing, view the page while signed
out and repeat the quickstart.

## Export

`--export DIR` copies the working bytes of **tracked files only**, excluding `.git`,
untracked generated environments, built-in credential-file patterns and manifest
exclusions. Stage or commit a new file first if it should ship. File contents are
not edited. Staged additions and uncommitted edits to tracked files are included
using their working bytes. A NOTICE identifies a source with tracked changes;
the notice does not change finding gates.
Built-in exclusions include `.env`, `.env.*`, `*.env`, `.npmrc`, SSH private-key
names such as `id_rsa` and `id_ed25519`, key/certificate files and credential/token
files. The credential list also includes `.git-credentials`, `.netrc`, `.pgpass`,
`.htpasswd`, `kubeconfig`, `.kube/config`, `.pypirc`, `*.jks`, `*.keystore`,
`terraform.tfstate`/`*.tfstate`, `.docker/config.json`, `keystore.properties`,
`*.pem`, `*.key`, `*.p12`, `*.pfx`, `credentials*` and `*token.json`.
These are still scanned in the source, but are left out of the export.
The copy gets one commit with a generic author and committer, a UTC date, no remote,
no active hooks and no original history. It is scanned again, including its new
commit and all license and quality checks. `--verify` also verifies the export.
A blocked export is a **private review artifact**. A failed or interrupted export
can leave a partial directory. Keep it private and use a new destination on retry;
existing paths are never overwritten. A blocked export can still contain the
reported credentials or personal data. Do not publish it; delete it after fixing
the source, then export again to a new folder.

The report records the export commit, file count and SHA-256 digest. Immediately
before publishing, and **before adding a remote**, run:

```sh
release-check EXPORT_DIR --check-digest DIGEST
```

Use the digest from the report. This needs no terms file and writes no report.
An unchanged export returns PASS (0); a changed or unclean export returns
FIX-THESE (1); a malformed digest, missing path or non-Git folder returns
INCOMPLETE (2) with a reason.

The digest requires one reachable commit across all refs and one on HEAD, exactly
one ref, `refs/heads/main`, no remote, no ignored files and clean status including
untracked files. Any tag (including annotated tags and tags on blobs or trees),
extra branch or custom ref invalidates it, even if no new commit was added.
The export's `.git/config` must retain exactly the generated core settings
(`repositoryformatversion=0`, `filemode=true`, `bare=false`, `logallrefupdates=true`),
with no edits or additions. Exports contain no hooks, including sample hooks.
The exact metadata file whitelist is HEAD, config, description, index,
info/exclude, refs/heads/main, logs/HEAD, logs/refs/heads/main and the loose
objects reachable from the single commit. Other files, symlinks, packs,
alternates, shallow metadata, grafts and attributes invalidate the check.
HEAD must remain attached to main; both reflogs must retain their one initial
commit entry. `git fsck --full --strict --unreachable --no-reflogs` must be clean.
Unexpected directories, including empty working directories, invalidate it too.

For independent verification, sort the raw paths from `git ls-files -z` as bytes.
For each regular, non-symlink file, append to an inner SHA-256: raw path, NUL,
ASCII decimal value of `st_mode & 0o111`, NUL, ASCII decimal `st_mtime_ns`, NUL,
working-file bytes, NUL. Next sort all relative `.git` entry paths lexically;
for each append its UTF-8 path, NUL, file bytes (or the ASCII word `directory`
for a directory), NUL. The `.git` prefix itself is omitted.
The export digest is SHA-256 of the ASCII HEAD object ID, NUL, then the inner
hexadecimal digest encoded as ASCII. No newline is included. This hashes working
bytes, metadata and the commit identity together. Touching files, refreshing the
index or repacking objects changes the digest; check the original export folder.

## Manifest and verification

`release-check.json` declares exclusions and commands. `--manifest PATH` can use
an external private manifest instead. `--verify` authorizes those reviewed commands;
without it, readiness remains blocked. No commands are inferred from README prose.
`argv` avoids shell interpretation.
A missing or malformed `--manifest` file returns INCOMPLETE (2); a malformed
in-repository `release-check.json` does too. An external manifest is not copied
into the export as `release-check.json`. Keep it available and pass `--manifest`
again to repeat verification of that export.

```json
{
  "exclude": ["deployment/", "local-config/"],
  "quickstart": [
    {"file": "README.md", "line": 17, "argv": ["python", "-m", "pip", "install", "."]},
    {"file": "README.md", "line": 18, "argv": ["release-check", "--help"]}
  ],
  "checks": [
    {"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}
  ],
  "approvals": []
}
```

Those line numbers are illustrative: use the line of that exact command in your
own README. The entire numbered line must contain only the command, inside a
fenced code block; do not use an inline command in an `Install:` sentence.
Each quickstart entry must match that line when split into arguments.
A missing document or a mismatch blocks verification before commands run.
Roles are `quickstart`, `tests`, `lint`, `types`, `build` and `syntax`.

Verification snapshots the tracked working files, clones the snapshot and creates
a fresh venv and HOME without inherited credentials. The first commands must
install the project and required test tools. Each command's exit code and output
fingerprint are recorded; raw output is discarded. `--timeout` bounds each command
(default 300 seconds). Pip may contact package indexes.

Approvals acknowledge a specific non-secret false positive or reviewed media file:
`scope`, `kind`, `path`, `fingerprint`, with an optional `reason` explaining it.
They apply to that exact scope/path/value, not every occurrence globally. Never
approve unseen media. Denylist hits and secret findings cannot be waived.
If the same finding appears in both the working tree and history, it needs two
approvals: one with `scope: tree` and one with `scope: history`. A tree approval
does not cover history, and a history approval does not cover the tree.
Review approvals as code changes.

Dependency license overrides are evidence-bound entries in `dependency_licenses`,
keyed by normalized installed distribution name, with `version`, `spdx` and full
`sha256` of an installed license file. They clarify ambiguous metadata such as a
generic BSD classifier; unknown, incompatible or missing evidence still blocks.
For an installed package with no license file, an entry may instead contain
`version` and `owner_disposition: {"spdx": "MIT", "source_url": "https://example.org/LICENSE",
"reviewed": true, "note": "Owner reviewed the upstream license for this version."}`.
The version must match, the SPDX expression must be allowlisted, and a nonempty
source URL and explicit review are required. Known incompatible or unknown SPDX
metadata still blocks. Accepted dispositions and their evidence appear in reports.
The allowlist includes MIT-CMU, CNRI-Python, Zlib, BSL-1.0 and
Apache-2.0 WITH LLVM-exception, including conservative AND/OR expressions.
The policy recognizes permissive/PSF/MPL license identifiers; license obligations
and source provenance still need human review.

## What is checked

- Working files, including untracked and ignored files other than untracked known
  dependency, cache and build directories. Only tracked files can enter an export.
- Every commit reachable from local refs and reflogs: author, committer, message,
  historical filenames and distinct blob/path pairs. Shallow history blocks both
  source audits and exports because historical attribution cannot be checked fully.
- Local ref and tag names, annotated tag contents and tagger identity, plus local
  configuration including remote URLs. These are discarded by the export.
- Emails with ordinary or quoted local parts, including HTML entities, URL-encoded
  at signs, fullwidth at signs and bracketed at/dot spellings. This is not a full
  email grammar or arbitrary obfuscation decoder.
- Phones shaped as US 3-3-4 groups, ten contiguous digits starting 2–9, local 0-prefixed 4/5+6
  groups, or 8–15 digits beginning with plus/00 and optional spaces, dots or
  hyphens. Dates and identifiers can need false-positive approvals.
- Standard dotted IPv4 and colon IPv6 literals, plus bracketed/spaced IPv4 dots.
  Hexadecimal, integer and octal IP encodings are not decoded. MAC addresses with
  colon, dash or dotted groups, or twelve hex digits labelled MAC/NIC, are reported.
- Internal host labels internal, local, lan, corp, intranet, private, test,
  localdomain and home (including home.arpa), in any dotted position, UNC hosts,
  tailnet hosts ending ts.net and name-NN shapes except common platform/encoding
  names. Common code receivers such as self/ctx/this are exempt. Owner domains
  must be supplied in the terms file; bare machine names remain manual.
- Home paths under home, Users, Volumes and mnt/home, Windows Users paths,
  user-specific tilde paths, UNC home paths and URL-encoded forms.
- Known-private owner/repo strings supplied by `--private-repo`, credential files,
  PEM keys, provider token prefixes, Basic/Bearer auth, credential URLs, CLI/XML
  and labelled secrets (including camelCase), password hashes and pgpass lines.
  Generic key labels exempt recognised public SPDX identifiers and short,
  unquoted lowercase map-field values. Attached generic -p values need at least
  eight token characters; mysql and sshpass have dedicated forms.
  Prose with an explicit is link is checked even for short values. Other bare
  prose labels have a 12-character floor for password and a 20-character floor
  for other labels. Netrc password directives also catch short values.
- Entropy candidates of 32+ letters/digits/underscore/slash/plus/equals/hyphen
  containing lower and upper case and a digit, with Shannon entropy at least 4.3.
  Pure hex strings are exempt except 32-hex token shapes or key/token/secret/auth/
  signing context. Context also catches long lowercase tokens. Recognised
  sha256/384/512 integrity values and lockfile hash fields are exempt from entropy
  only, as are valid base64 data URIs. URL path segments are checked separately
  rather than combined into one token. Explicit secret rules still apply.
  Media needs human review.
- Standard MIT wording and license metadata; installed dependency metadata and
  license-file evidence. NOTICE, UPSTREAM and license files are protected.
- README, limitations, CONTRIBUTING, SECURITY, issue templates, tests and declared
  quickstart, test, lint and type commands. Configured Ruff/mypy checks must be listed.

Pass known-private repositories with repeated `--private-repo owner/name` flags.
The tool never calls a hosting API to infer visibility. Supply this list separately;
public and private URLs look the same without that evidence.

## Reports and privacy

Exactly two files, `report.json` and `report.md`, are written under
`<report-root>/<repo>/<UTC-timestamp>/`, with a 0700 run directory and 0600 files.
The reports hold counts, statuses, safe relative paths, line numbers, term indices,
object IDs and SHA-256 fingerprints (first 16 hex characters). Private filenames
become path fingerprints. No matched content, command output or terms are included.
The terminal prints only a relative report locator, never your reports root.
A report still describes a private repository: **keep it private**.

## Honest limitations

This is a release gate, not a security or legal guarantee. Only the standard MIT
text passes automatically. Tests and dependency checks assume a Python project;
other dependency ecosystems always need manual review and cannot reach PASS.
Malformed `pyproject.toml` or invalid manifest commands can end an audit as INCOMPLETE.
Names and people absent from the private terms file are not checked. Unicode and
word-separator normalisation cover only the forms listed above. Arbitrarily
spaced letters, homoglyphs, leetspeak, base64-encoded terms, split strings and
computed credentials are not decoded. UTF-32 text is not interpreted.

False positives are expected, including machine-shaped identifiers, loopback
addresses, placeholder email addresses at example domains, version strings,
phone-shaped identifiers and 32-hex digests. Deliberate public examples need
exact scope/path/fingerprint approvals; these domains are not blanket exemptions.
Entropy cannot identify every secret.
The tool does not OCR images, recognize faces, unpack archives, discover nonlocal
Git refs or audit unreachable source objects, or inspect anything on the hosting site. It never
fetches history. Obtain any needed history yourself before auditing.

Symlinks and submodules block coverage and are never followed or exported. Git LFS
pointers block unscanned external content. Archives and binary formats need human
review. System and global Git configuration are disabled for audit Git operations;
export commits disable hooks and signing.

There is no file-size limit. Large files and long histories can make scans slow
and use substantial memory. `--timeout` bounds declared commands, not scanning.

Fresh HOME/venv isolates credentials and caches; it is not a security sandbox.
Only verify repositories and commands you trust: their code can access the machine
and network. Browser, account, hardware and deployment checks stay manual.
The tool starts no services or timers itself.

## Related tools

Secret scanning and history rewriting are well served by established tools such as
gitleaks, trufflehog and git-filter-repo. This tool adds the plan, the one-commit
export and the test list in one local command.

## Development

```sh
python3 -m unittest discover -s tests -q
```

Run the suite one process at a time; the full suite takes about two minutes.
Tests use synthetic repositories and temporary
terms files; they do not load user privacy files or contact network services.
