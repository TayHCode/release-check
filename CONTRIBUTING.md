# Contributing

Keep the runtime dependency list empty and tests synthetic. Run
`python3 -m unittest discover -s tests -q` before submitting changes.
Add regression fixtures for privacy/reporting, history coverage or export behavior.
Never include actual credentials or personal term lists in issues or fixtures.

The tool stays one standard-library file, `release_check.py`. Every finding kind
needs a fix sentence. Output and reports must never include matched text or raw
command output. Run the suite one process at a time.
