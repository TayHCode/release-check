import json
from pathlib import Path
import unittest

import release_check as rc


class LicenseDispositionTests(unittest.TestCase):
    def audit(self, expression=None, license_text=None, files=None, **entry):
        package = dict(name="fixture", version="1", expression=expression,
                       license=license_text, classifiers=[], license_files=files or [])
        scanner = rc.Scanner([])
        result = rc.dependency_audit(json.dumps([package]).encode(), Path('.'), scanner,
                                     {"dependency_licenses": {"fixture": entry}})
        self.assertEqual(len(scanner.findings), result["blocked"])
        return result

    def disposition(self, **changes):
        return dict(spdx="MIT", source_url="https://example.org/LICENSE",
                    reviewed=True, note="Owner reviewed version 1.", **changes)

    def test_new_spdx_ids_and_expression_forms(self):
        for identifier in ("MIT-CMU", "CNRI-Python", "Zlib", "BSL-1.0",
                           "Apache-2.0 WITH LLVM-exception"):
            for label in (identifier, f"({identifier} AND MIT)", f"MIT OR ({identifier})"):
                for field in ("expression", "license_text"):
                    with self.subTest(label=label, field=field):
                        result = self.audit(**{field: label}, files=[{"hash": "f" * 64}])
                        self.assertEqual(result["blocked"], 0)

    def test_owner_disposition_accepts_and_reports_evidence(self):
        disposition = self.disposition()
        result = self.audit(version="1", owner_disposition=disposition)
        self.assertEqual(result["blocked"], 0)
        self.assertEqual(result["owner_dispositions"], [dict(package="fixture", version="1", owner_disposition=disposition)])
        report = dict(version=rc.VERSION, ready=True, findings=[], counts={},
                      verification={"dependencies": result}, license={})
        for output_text in (rc.format_text(report), rc.format_markdown(report)):
            for value in ("OWNER LICENSE DISPOSITIONS", disposition["source_url"], disposition["note"], '"reviewed": true'):
                self.assertIn(value, output_text)

    def test_disposition_version_mismatch_refused(self):
        self.assertEqual(self.audit(version="2", owner_disposition=self.disposition())["blocked"], 1)

    def test_disposition_missing_source_refused(self):
        for value in (None, "", "   ", False):
            disposition = self.disposition()
            disposition["source_url"] = value
            with self.subTest(source=value):
                self.assertEqual(self.audit(version="1", owner_disposition=disposition)["blocked"], 1)
        disposition.pop("source_url")
        self.assertEqual(self.audit(version="1", owner_disposition=disposition)["blocked"], 1)

    def test_disposition_non_allowlisted_spdx_refused(self):
        for spdx in ("GPL-3.0-only", "AGPL-3.0-only", "CC-BY-NC-4.0", "unknown", "MIT OR unknown", None, []):
            disposition = self.disposition()
            disposition["spdx"] = spdx
            with self.subTest(spdx=spdx):
                result = self.audit(version="1", owner_disposition=disposition)
                self.assertEqual(result["blocked"], 1)
                self.assertEqual(result["owner_dispositions"], [])

    def test_unknown_and_restricted_metadata_still_block(self):
        for expression in ("unknown", "GPL-3.0-only", "AGPL-3.0-only", "CC-BY-NC-4.0", "MIT OR unknown"):
            with self.subTest(expression=expression):
                self.assertEqual(self.audit(expression=expression, files=[{"hash": "f" * 64}])["blocked"], 1)
                self.assertEqual(self.audit(expression=expression, version="1", owner_disposition=self.disposition())["blocked"], 1)

    def test_unknown_and_restricted_free_text_still_block(self):
        for license_text in ("unknown", "GPL-3.0-only", "AGPL-3.0-only", "non-commercial"):
            with self.subTest(license_text=license_text):
                self.assertEqual(self.audit(license_text=license_text, version="1", owner_disposition=self.disposition())["blocked"], 1)

    def test_disposition_requires_explicit_review(self):
        for reviewed in (False, None, 1, "true"):
            disposition = self.disposition()
            disposition["reviewed"] = reviewed
            self.assertEqual(self.audit(version="1", owner_disposition=disposition)["blocked"], 1)

    def test_missing_license_without_disposition_still_blocks(self):
        self.assertEqual(self.audit(expression="MIT", version="1", spdx="MIT", sha256="f" * 64)["blocked"], 1)

    def test_disposition_cannot_replace_installed_file_evidence(self):
        self.assertEqual(self.audit(expression="unknown", files=[{"hash": "f" * 64}], version="1", owner_disposition=self.disposition())["blocked"], 1)

    def test_installed_file_hash_and_version_still_required(self):
        for version, digest, blocked in (("1", "f" * 64, 0), ("2", "f" * 64, 1), ("1", "a" * 64, 1)):
            self.assertEqual(self.audit(expression="BSD", files=[{"hash": "f" * 64}], version=version, spdx="BSD-3-Clause", sha256=digest)["blocked"], blocked)
