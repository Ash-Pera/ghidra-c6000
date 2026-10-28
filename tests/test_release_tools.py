# SPDX-License-Identifier: Apache-2.0
"""Guard against false-positive verification and incomplete/private archives."""
from pathlib import Path
import sys
import tempfile
import unittest
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_archive import check_archive
from verify import success_lines


class ReleaseToolsTest(unittest.TestCase):
    def archive(self, directory, *, omit=None, extra=None, version="12.2"):
        files = {
            "extension.properties": f"name=C6000\nversion={version}\n",
            "Module.manifest": "MODULE FILE LICENSE: Apache License 2.0\n",
            "lib/C6000.jar": "jar", "LICENSE": "license", "NOTICE.md": "notice",
            "data/languages/c6000.ldefs": "definitions",
            "data/languages/c6000.opinion": "opinion",
        }
        files.update({f"data/languages/{name}.sla": "compiled" for name in
                      ("c6000_le", "c6000_be", "c6000_le_analysis", "c6000_be_analysis")})
        if omit:
            del files[omit]
        if extra:
            files[extra] = "local material"
        path = Path(directory) / "candidate.zip"
        with ZipFile(path, "w") as output:
            for member, contents in files.items():
                output.writestr(member if member.startswith("/") else "C6000/" + member, contents)
        return path

    def test_complete_compatible_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            check_archive(self.archive(directory), "12.2")

    def test_missing_runtime_components_fail(self):
        for member in ("lib/C6000.jar", "data/languages/c6000_be_analysis.sla"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "Missing archive"):
                    check_archive(self.archive(directory, omit=member))

    def test_private_files_and_path_traversal_fail(self):
        for member in ("scratch/firmware.bin", ".research/manual.txt",
                       "tools/__pycache__/verify.pyc", "../outside", "/absolute"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "Unexpected archive"):
                    check_archive(self.archive(directory, extra=member))

    def test_wrong_ghidra_compatibility_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "compatibility"):
                check_archive(self.archive(directory, version="12.1.3"), "12.2")

    def test_real_script_completion_is_recognized(self):
        output = "INFO C6000ReturnDelayTest.java> C6000_RETURN_DELAY_OK cases=17 (GhidraScript)\n"
        self.assertIn("cases=17", success_lines(output, "C6000_RETURN_DELAY_OK"))

    def test_logged_marker_is_not_completion(self):
        for output in ("INFO command includes C6000_RETURN_DELAY_OK\n",
                       "java.lang.AssertionError: C6000_RETURN_DELAY_OK cases=17\n", ""):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                success_lines(output, "C6000_RETURN_DELAY_OK")

    def test_empty_or_duplicate_completion_fails(self):
        for output in ("C6000_RETURN_DELAY_OK cases=0\n",
                       "C6000_RETURN_DELAY_OK cases=17\nC6000_RETURN_DELAY_OK cases=17\n"):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                success_lines(output, "C6000_RETURN_DELAY_OK")


if __name__ == "__main__":
    unittest.main()
