"""Tests for sandbox.execution_orchestrator."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from sandbox.execution_orchestrator import (
    BACKEND_DOCKER,
    DecisionEngineStaticValidator,
    SandboxConfig,
    SandboxLimits,
    SandboxedExecutionOrchestrator,
    STATUS_SKIPPED_DEPENDENCY,
    STATUS_SUCCESS,
    STATUS_TIMEOUT,
    STATUS_VALIDATION_FAILED,
)


class TestValidationGate(unittest.TestCase):

    def test_rejects_unvalidated_unit(self):
        orch = SandboxedExecutionOrchestrator()
        result = orch.execute_unit({"unit_id": "u1", "code": "print('x')"}).to_dict()
        self.assertEqual(result["status"], STATUS_VALIDATION_FAILED)
        self.assertIn("missing_static_validation_pass", result["validation_reasons"])

    def test_accepts_explicitly_validated_unit(self):
        orch = SandboxedExecutionOrchestrator()
        result = orch.execute_unit(
            {
                "unit_id": "u1",
                "code": "print('ok')",
                "static_validation": {"passed": True},
            }
        ).to_dict()
        self.assertEqual(result["status"], STATUS_SUCCESS)
        self.assertEqual(result["stdout"].strip(), "ok")


class TestRuntimeControls(unittest.TestCase):

    def test_captures_stdout_stderr(self):
        orch = SandboxedExecutionOrchestrator(limits=SandboxLimits(timeout_seconds=2.0))
        result = orch.execute_unit(
            {
                "unit_id": "u2",
                "code": "import sys\nprint('hello')\nprint('warn', file=sys.stderr)",
                "static_validation": {"passed": True},
            }
        ).to_dict()
        self.assertEqual(result["status"], STATUS_SUCCESS)
        self.assertIn("hello", result["stdout"])
        self.assertIn("warn", result["stderr"])

    def test_times_out_runaway_process(self):
        orch = SandboxedExecutionOrchestrator(limits=SandboxLimits(timeout_seconds=0.3, cpu_seconds=1))
        result = orch.execute_unit(
            {
                "unit_id": "u3",
                "code": "while True:\n    pass\n",
                "static_validation": {"passed": True},
            }
        ).to_dict()
        self.assertEqual(result["status"], STATUS_TIMEOUT)


class TestDependencyAwareRun(unittest.TestCase):

    def test_skips_unit_when_dependency_failed(self):
        orch = SandboxedExecutionOrchestrator(limits=SandboxLimits(timeout_seconds=1.0))
        out = orch.execute_units(
            [
                {
                    "unit_id": "a",
                    "code": "raise RuntimeError('boom')",
                    "static_validation": {"passed": True},
                },
                {
                    "unit_id": "b",
                    "code": "print('should-not-run')",
                    "dependency_ids": ["a"],
                    "static_validation": {"passed": True},
                },
            ]
        )
        by_id = {r["unit_id"]: r for r in out["results"]}
        self.assertEqual(by_id["b"]["status"], STATUS_SKIPPED_DEPENDENCY)


class TestDockerBackendPath(unittest.TestCase):

    def test_docker_backend_invokes_docker_command(self):
        captured: dict[str, list[str]] = {}

        class _FakeProc:
            returncode = 0
            pid = 12345

            def communicate(self, timeout=None):
                return "ok\n", ""

            def wait(self, timeout=None):
                return 0

        def _fake_popen(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            return _FakeProc()

        orch = SandboxedExecutionOrchestrator(
            config=SandboxConfig(backend=BACKEND_DOCKER, docker_command="docker", docker_image="python:3.12-alpine")
        )

        with patch("sandbox.execution_orchestrator.subprocess.Popen", side_effect=_fake_popen):
            result = orch.execute_unit(
                {
                    "unit_id": "u4",
                    "code": "print('ok')",
                    "static_validation": {"passed": True},
                }
            ).to_dict()

        self.assertEqual(result["status"], STATUS_SUCCESS)
        self.assertTrue(captured["cmd"][0].endswith("docker"))
        self.assertIn("run", captured["cmd"])


class TestDecisionValidator(unittest.TestCase):

    def test_decision_validator_flags_unsafe_code(self):
        validator = DecisionEngineStaticValidator()
        passed, reasons, _ = validator.validate({"unit_id": "u5", "code": "eval('1+1')"})
        self.assertFalse(passed)
        self.assertIn("dynamic_execution_primitive_detected", reasons)


if __name__ == "__main__":
    unittest.main()
