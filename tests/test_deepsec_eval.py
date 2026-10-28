"""Regression checks for the accuracy of the DeepSec evaluation report."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVALUATOR = ROOT / "scripts" / "eval_deepsec_skill.py"


class DeepSecEvalReportTests(unittest.TestCase):
    def test_absent_security_scanner_cannot_report_approval(self):
        with tempfile.TemporaryDirectory() as temporary_home:
            env = {**os.environ, "HOME": temporary_home}
            result = subprocess.run(
                [sys.executable, str(EVALUATOR)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Security:   NOT_RUN", result.stdout)
        self.assertIn("Status:     INCOMPLETE", result.stdout)
        self.assertNotIn("Security:   APPROVE", result.stdout)

    def test_valid_config_path_containing_quote_is_safe(self):
        validator = ROOT / "skills/deepsec/scripts/validate-config.sh"
        template = ROOT / "skills/deepsec/assets/config.template.json"
        with tempfile.TemporaryDirectory() as work_dir:
            unusual_path = Path(work_dir) / "config'quoted.json"
            unusual_path.write_bytes(template.read_bytes())
            result = subprocess.run(
                [str(validator), str(unusual_path)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALID:", result.stdout)

    def test_placeholder_node_cli_is_not_treated_as_a_working_runner(self):
        detector = ROOT / "skills/deepsec/scripts/detect-runtime.sh"
        with tempfile.TemporaryDirectory() as work_dir:
            fake_npx = Path(work_dir) / "npx"
            fake_npx.write_text("#!/bin/sh\necho placeholder\n", encoding="utf-8")
            fake_npx.chmod(0o755)
            result = subprocess.run(
                [str(detector)],
                cwd=work_dir,
                env={**os.environ, "PATH": f"{work_dir}:/usr/bin:/bin"},
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("node:", result.stdout)

    def test_placeholder_cli_exits_nonzero_without_scan_evidence(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        result = subprocess.run(
            [node, str(ROOT / "skills/deepsec/bin/cli.js")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not implemented", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
