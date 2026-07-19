"""Sandboxed execution orchestrator for validated Python execution units."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

try:
    import resource
except Exception:  # pragma: no cover - platform guard
    resource = None  # type: ignore[assignment]

from analysis.capability import analyze_to_dict as capability_to_dict
from analysis.decision import (
    CONDITIONALLY_SAFE,
    SAFE,
    ExecutionPolicy,
    ExecutionPolicyEngine,
    ExternalAccessPolicy,
    SafetyDecisionEngine,
)
from analysis.resource import analyze_to_dict as resource_to_dict
from analysis.taint import analyze_to_dict as taint_to_dict

STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_VALIDATION_FAILED = "VALIDATION_FAILED"
STATUS_SKIPPED_DEPENDENCY = "SKIPPED_DEPENDENCY"

BACKEND_SUBPROCESS = "subprocess"
BACKEND_DOCKER = "docker"


class StaticValidator(Protocol):
    def validate(self, unit: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
        ...


@dataclass(frozen=True)
class SandboxLimits:
    cpu_seconds: int = 2
    memory_bytes: int = 256 * 1024 * 1024
    timeout_seconds: float = 5.0
    kill_grace_seconds: float = 0.25


@dataclass(frozen=True)
class SandboxConfig:
    backend: str = BACKEND_SUBPROCESS
    python_executable: str = sys.executable
    docker_command: str = "docker"
    docker_image: str = "python:3.12-alpine"
    docker_network: str = "none"


@dataclass
class ExecutionRecord:
    unit_id: str
    status: str
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    started_at: float | None = None
    finished_at: float | None = None
    duration_seconds: float = 0.0
    dependency_ids: list[str] = field(default_factory=list)
    validation_reasons: list[str] = field(default_factory=list)
    validation_metadata: dict[str, Any] = field(default_factory=dict)
    runtime_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "status": self.status,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "dependency_ids": self.dependency_ids,
            "validation_reasons": self.validation_reasons,
            "validation_metadata": self.validation_metadata,
            "runtime_metadata": self.runtime_metadata,
        }


class MetadataStaticValidator:
    """Strict metadata validator: only explicitly passed units are executable."""

    def validate(self, unit: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
        static_validation = unit.get("static_validation")
        if isinstance(static_validation, dict):
            if bool(static_validation.get("passed", False)):
                return True, [], {"source": "unit.static_validation"}

            verdict = static_validation.get("verdict")
            if verdict in {SAFE, CONDITIONALLY_SAFE}:
                return True, [], {"source": "unit.static_validation", "verdict": verdict}

            reasons = list(static_validation.get("reasons", []))
            return False, reasons or ["unit_static_validation_failed"], {
                "source": "unit.static_validation",
                "verdict": verdict,
            }

        if bool(unit.get("validated", False)):
            return True, [], {"source": "unit.validated"}

        return False, ["missing_static_validation_pass"], {"source": "metadata"}


class DecisionEngineStaticValidator:
    """Static validator that routes unit code through the safety decision system."""

    def __init__(
        self,
        *,
        execution_policy: ExecutionPolicy | None = None,
        allow_conditionally_safe: bool = False,
    ) -> None:
        self._execution_policy = execution_policy
        self._allow_conditionally_safe = allow_conditionally_safe

    def validate(self, unit: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
        code = str(unit.get("code", ""))
        unit_name = str(unit.get("unit_id", "<unit>"))

        taint_results = taint_to_dict(code)
        capability_results = capability_to_dict(code, name=unit_name)
        resource_results = resource_to_dict(code, name=unit_name)

        if self._execution_policy is None:
            decision = SafetyDecisionEngine(policies=[ExternalAccessPolicy()]).evaluate(
                taint_results=taint_results,
                capability_results=capability_results,
                resource_results=resource_results,
            )
        else:
            decision = ExecutionPolicyEngine(
                policy=self._execution_policy,
                base_policies=[ExternalAccessPolicy()],
            ).evaluate(
                taint_results=taint_results,
                capability_results=capability_results,
                resource_results=resource_results,
            )

        verdict = decision.verdict
        passed = verdict == SAFE or (self._allow_conditionally_safe and verdict == CONDITIONALLY_SAFE)
        return passed, list(decision.reasons), {"decision": decision.to_dict()}


class SandboxedExecutionOrchestrator:
    """Executes validated Python units in isolated subprocess or Docker sandboxes."""

    def __init__(
        self,
        *,
        limits: SandboxLimits | None = None,
        config: SandboxConfig | None = None,
        validator: StaticValidator | None = None,
    ) -> None:
        self._limits = limits or SandboxLimits()
        self._config = config or SandboxConfig()
        self._validator = validator or MetadataStaticValidator()

    def execute_units(self, units: list[dict[str, Any]]) -> dict[str, Any]:
        by_id: dict[str, dict[str, Any]] = {}
        for idx, unit in enumerate(units, start=1):
            unit_id = str(unit.get("unit_id", f"unit_{idx}"))
            normalized = dict(unit)
            normalized["unit_id"] = unit_id
            by_id[unit_id] = normalized

        pending = set(by_id.keys())
        done: dict[str, ExecutionRecord] = {}

        while pending:
            ready: list[str] = []
            blocked: list[str] = []

            for unit_id in sorted(pending):
                deps = self._dependency_ids(by_id[unit_id])
                unmet = [dep for dep in deps if dep not in done]
                if unmet:
                    blocked.append(unit_id)
                    continue

                failed_deps = [dep for dep in deps if done[dep].status != STATUS_SUCCESS]
                if failed_deps:
                    done[unit_id] = ExecutionRecord(
                        unit_id=unit_id,
                        status=STATUS_SKIPPED_DEPENDENCY,
                        dependency_ids=deps,
                        validation_reasons=[f"dependency_not_success:{d}" for d in failed_deps],
                    )
                    continue

                ready.append(unit_id)

            if not ready and all(uid in done for uid in pending):
                pending = {uid for uid in pending if uid not in done}
                continue

            if not ready:
                for unit_id in blocked:
                    if unit_id in done:
                        continue
                    deps = self._dependency_ids(by_id[unit_id])
                    done[unit_id] = ExecutionRecord(
                        unit_id=unit_id,
                        status=STATUS_SKIPPED_DEPENDENCY,
                        dependency_ids=deps,
                        validation_reasons=["dependency_cycle_or_missing_dependency"],
                    )
                pending = {uid for uid in pending if uid not in done}
                continue

            for unit_id in ready:
                if unit_id in done:
                    continue
                done[unit_id] = self.execute_unit(by_id[unit_id])

            pending = {uid for uid in pending if uid not in done}

        records = [done[uid].to_dict() for uid in sorted(done.keys())]
        return {
            "backend": self._config.backend,
            "limits": {
                "cpu_seconds": self._limits.cpu_seconds,
                "memory_bytes": self._limits.memory_bytes,
                "timeout_seconds": self._limits.timeout_seconds,
            },
            "results": records,
            "summary": {
                "total": len(records),
                "success": sum(1 for r in records if r["status"] == STATUS_SUCCESS),
                "failed": sum(1 for r in records if r["status"] == STATUS_FAILED),
                "timeouts": sum(1 for r in records if r["status"] == STATUS_TIMEOUT),
                "validation_failed": sum(1 for r in records if r["status"] == STATUS_VALIDATION_FAILED),
                "skipped_dependency": sum(1 for r in records if r["status"] == STATUS_SKIPPED_DEPENDENCY),
            },
        }

    def execute_unit(self, unit: dict[str, Any]) -> ExecutionRecord:
        unit_id = str(unit.get("unit_id", "<unit>"))
        deps = self._dependency_ids(unit)

        passed, reasons, validation_meta = self._validator.validate(unit)
        if not passed:
            return ExecutionRecord(
                unit_id=unit_id,
                status=STATUS_VALIDATION_FAILED,
                dependency_ids=deps,
                validation_reasons=reasons,
                validation_metadata=validation_meta,
            )

        started = time.time()
        if self._config.backend == BACKEND_DOCKER:
            status, return_code, out, err, runtime_meta = self._run_in_docker(code=str(unit.get("code", "")))
        else:
            status, return_code, out, err, runtime_meta = self._run_in_subprocess(code=str(unit.get("code", "")))
        finished = time.time()

        return ExecutionRecord(
            unit_id=unit_id,
            status=status,
            return_code=return_code,
            stdout=out,
            stderr=err,
            started_at=started,
            finished_at=finished,
            duration_seconds=max(0.0, finished - started),
            dependency_ids=deps,
            validation_reasons=reasons,
            validation_metadata=validation_meta,
            runtime_metadata=runtime_meta,
        )

    @staticmethod
    def _dependency_ids(unit: dict[str, Any]) -> list[str]:
        deps = unit.get("dependency_ids", [])
        if not isinstance(deps, list):
            return []
        return [str(d) for d in deps]

    def _run_in_subprocess(self, *, code: str) -> tuple[str, int | None, str, str, dict[str, Any]]:
        with tempfile.TemporaryDirectory(prefix="cerco-sbx-") as td:
            script_path = Path(td) / "unit.py"
            script_path.write_text(code, encoding="utf-8")

            cmd = [self._config.python_executable, "-I", "-S", str(script_path)]
            return self._spawn_and_collect(
                cmd=cmd,
                preexec_fn=self._resource_limiter_preexec(),
                runtime_metadata={"sandbox": "subprocess", "script_path": str(script_path)},
            )

    def _run_in_docker(self, *, code: str) -> tuple[str, int | None, str, str, dict[str, Any]]:
        with tempfile.TemporaryDirectory(prefix="cerco-docker-") as td:
            script_path = Path(td) / "unit.py"
            script_path.write_text(code, encoding="utf-8")

            cmd = [
                self._config.docker_command,
                "run",
                "--rm",
                "--network",
                self._config.docker_network,
                "--memory",
                str(self._limits.memory_bytes),
                "--cpus",
                "1.0",
                "-v",
                f"{script_path}:/work/unit.py:ro",
                "-w",
                "/work",
                self._config.docker_image,
                "python",
                "-I",
                "-S",
                "unit.py",
            ]
            return self._spawn_and_collect(
                cmd=cmd,
                preexec_fn=self._resource_limiter_preexec(),
                runtime_metadata={"sandbox": "docker", "image": self._config.docker_image},
            )

    def _spawn_and_collect(
        self,
        *,
        cmd: list[str],
        preexec_fn: Any,
        runtime_metadata: dict[str, Any],
    ) -> tuple[str, int | None, str, str, dict[str, Any]]:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=preexec_fn,
            )
        except FileNotFoundError as exc:
            return STATUS_FAILED, None, "", str(exc), {**runtime_metadata, "spawn_error": "command_not_found"}

        try:
            out, err = proc.communicate(timeout=self._limits.timeout_seconds)
        except subprocess.TimeoutExpired:
            self._terminate_process_tree(proc)
            out, err = proc.communicate()
            return (
                STATUS_TIMEOUT,
                proc.returncode,
                out,
                (err + "\n" if err else "") + f"execution_timeout_exceeded:{self._limits.timeout_seconds}s",
                {**runtime_metadata, "timed_out": True},
            )

        status = STATUS_SUCCESS if proc.returncode == 0 else STATUS_FAILED
        return status, proc.returncode, out, err, runtime_metadata

    def _resource_limiter_preexec(self):
        if os.name != "posix":  # pragma: no cover - non-posix guard
            return None

        cpu = int(self._limits.cpu_seconds)
        mem = int(self._limits.memory_bytes)

        def _preexec() -> None:
            os.setsid()
            if resource is None:
                return
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            except Exception:
                pass

        return _preexec

    def _terminate_process_tree(self, proc: subprocess.Popen[Any]) -> None:
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                pass
        else:  # pragma: no cover - non-posix guard
            try:
                proc.terminate()
            except Exception:
                pass

        try:
            proc.wait(timeout=self._limits.kill_grace_seconds)
            return
        except Exception:
            pass

        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        else:  # pragma: no cover - non-posix guard
            try:
                proc.kill()
            except Exception:
                pass


__all__ = [
    "BACKEND_DOCKER",
    "BACKEND_SUBPROCESS",
    "DecisionEngineStaticValidator",
    "ExecutionRecord",
    "MetadataStaticValidator",
    "SandboxConfig",
    "SandboxLimits",
    "SandboxedExecutionOrchestrator",
    "STATUS_FAILED",
    "STATUS_SKIPPED_DEPENDENCY",
    "STATUS_SUCCESS",
    "STATUS_TIMEOUT",
    "STATUS_VALIDATION_FAILED",
]
