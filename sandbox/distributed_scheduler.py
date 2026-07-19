"""Lightweight distributed scheduler for validated execution units."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .execution_orchestrator import (
    STATUS_FAILED,
    STATUS_SKIPPED_DEPENDENCY,
    STATUS_SUCCESS,
    STATUS_TIMEOUT,
    STATUS_VALIDATION_FAILED,
    MetadataStaticValidator,
    SandboxConfig,
    SandboxLimits,
    SandboxedExecutionOrchestrator,
    StaticValidator,
)

STATUS_BLOCKED_UNSAFE = "BLOCKED_UNSAFE"
STATUS_UNASSIGNED = "UNASSIGNED"


class UnitExecutor(Protocol):
    def execute(self, *, node: "VolunteerNode", unit: dict[str, Any]) -> dict[str, Any]:
        ...


@dataclass
class VolunteerNode:
    """Represents a volunteer worker with constrained resources."""

    node_id: str
    total_cpu_units: int
    total_memory_bytes: int
    max_concurrent_tasks: int = 1
    labels: list[str] = field(default_factory=list)
    supported_backends: tuple[str, ...] = ("subprocess", "docker")

    available_cpu_units: int = field(init=False)
    available_memory_bytes: int = field(init=False)
    running_tasks: int = field(default=0, init=False)
    completed_tasks: int = field(default=0, init=False)
    failed_tasks: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.available_cpu_units = self.total_cpu_units
        self.available_memory_bytes = self.total_memory_bytes

    def can_run(self, *, cpu_units: int, memory_bytes: int) -> bool:
        return (
            self.running_tasks < self.max_concurrent_tasks
            and self.available_cpu_units >= cpu_units
            and self.available_memory_bytes >= memory_bytes
        )

    def reserve(self, *, cpu_units: int, memory_bytes: int) -> None:
        self.running_tasks += 1
        self.available_cpu_units -= cpu_units
        self.available_memory_bytes -= memory_bytes

    def release(self, *, cpu_units: int, memory_bytes: int, success: bool) -> None:
        self.running_tasks = max(0, self.running_tasks - 1)
        self.available_cpu_units = min(self.total_cpu_units, self.available_cpu_units + cpu_units)
        self.available_memory_bytes = min(self.total_memory_bytes, self.available_memory_bytes + memory_bytes)
        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1

    def snapshot(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "total_cpu_units": self.total_cpu_units,
            "total_memory_bytes": self.total_memory_bytes,
            "available_cpu_units": self.available_cpu_units,
            "available_memory_bytes": self.available_memory_bytes,
            "running_tasks": self.running_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "labels": list(self.labels),
            "supported_backends": list(self.supported_backends),
        }


@dataclass(frozen=True)
class UnitRequirements:
    cpu_units: int = 1
    memory_bytes: int = 64 * 1024 * 1024


class LocalSandboxExecutor:
    """Default executor using local sandbox orchestration per unit."""

    def __init__(
        self,
        *,
        limits: SandboxLimits | None = None,
        config: SandboxConfig | None = None,
    ) -> None:
        self._orchestrator = SandboxedExecutionOrchestrator(
            limits=limits,
            config=config,
            validator=_AlwaysPassValidator(),
        )

    def execute(self, *, node: VolunteerNode, unit: dict[str, Any]) -> dict[str, Any]:
        result = self._orchestrator.execute_unit(unit).to_dict()
        result.setdefault("runtime_metadata", {})
        result["runtime_metadata"]["node_id"] = node.node_id
        return result


class _AlwaysPassValidator:
    def validate(self, unit: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
        return True, [], {"source": "scheduler"}


class DistributedTaskScheduler:
    """Resource-aware scheduler for validated execution units on volunteer nodes."""

    def __init__(
        self,
        *,
        validator: StaticValidator | None = None,
        executor: UnitExecutor | None = None,
        max_retries: int = 1,
    ) -> None:
        self._validator = validator or MetadataStaticValidator()
        self._executor = executor or LocalSandboxExecutor()
        self._max_retries = max(0, int(max_retries))

    def schedule(
        self,
        *,
        execution_units: list[dict[str, Any]],
        nodes: list[VolunteerNode],
    ) -> dict[str, Any]:
        units: dict[str, dict[str, Any]] = {}
        for idx, unit in enumerate(execution_units, start=1):
            unit_id = str(unit.get("unit_id", f"unit_{idx}"))
            n = dict(unit)
            n["unit_id"] = unit_id
            n.setdefault("dependency_ids", [])
            units[unit_id] = n

        attempts: dict[str, int] = {u: 0 for u in units}
        final_results: dict[str, dict[str, Any]] = {}
        assignment_log: list[dict[str, Any]] = []

        pending = set(units.keys())
        while pending:
            progressed = False

            ready = [
                uid
                for uid in sorted(pending)
                if self._deps_satisfied(uid, units=units, results=final_results)
            ]

            for unit_id in ready:
                if unit_id in final_results:
                    continue

                unit = units[unit_id]
                deps = [str(x) for x in unit.get("dependency_ids", [])]

                failed_deps = [d for d in deps if final_results.get(d, {}).get("status") != STATUS_SUCCESS]
                if failed_deps:
                    final_results[unit_id] = {
                        "unit_id": unit_id,
                        "status": STATUS_SKIPPED_DEPENDENCY,
                        "dependency_ids": deps,
                        "validation_reasons": [f"dependency_not_success:{d}" for d in failed_deps],
                    }
                    progressed = True
                    continue

                passed, reasons, validation_meta = self._validator.validate(unit)
                if not passed:
                    final_results[unit_id] = {
                        "unit_id": unit_id,
                        "status": STATUS_BLOCKED_UNSAFE,
                        "dependency_ids": deps,
                        "validation_reasons": reasons,
                        "validation_metadata": validation_meta,
                    }
                    progressed = True
                    continue

                req = self._requirements_for(unit)
                node = self._select_node(nodes=nodes, requirements=req)
                if node is None:
                    # no fit currently; try in next pass, or mark unassigned if nothing can fit
                    continue

                attempts[unit_id] += 1
                started = time.time()
                node.reserve(cpu_units=req.cpu_units, memory_bytes=req.memory_bytes)
                try:
                    outcome = self._executor.execute(node=node, unit=unit)
                finally:
                    success = outcome.get("status") == STATUS_SUCCESS if isinstance(outcome, dict) else False
                    node.release(cpu_units=req.cpu_units, memory_bytes=req.memory_bytes, success=success)

                finished = time.time()
                status = str(outcome.get("status", STATUS_FAILED))

                assignment_log.append(
                    {
                        "unit_id": unit_id,
                        "node_id": node.node_id,
                        "attempt": attempts[unit_id],
                        "status": status,
                        "started_at": started,
                        "finished_at": finished,
                        "duration_seconds": max(0.0, finished - started),
                        "requirements": {"cpu_units": req.cpu_units, "memory_bytes": req.memory_bytes},
                        "node_snapshot": node.snapshot(),
                    }
                )

                if status == STATUS_SUCCESS:
                    final_results[unit_id] = {
                        **outcome,
                        "unit_id": unit_id,
                        "dependency_ids": deps,
                        "attempts": attempts[unit_id],
                    }
                    progressed = True
                    continue

                retryable = status in {STATUS_FAILED, STATUS_TIMEOUT, STATUS_VALIDATION_FAILED}
                if retryable and attempts[unit_id] <= self._max_retries:
                    progressed = True
                    continue

                final_results[unit_id] = {
                    **outcome,
                    "unit_id": unit_id,
                    "dependency_ids": deps,
                    "attempts": attempts[unit_id],
                }
                progressed = True

            pending = {u for u in pending if u not in final_results}

            if progressed:
                continue

            # deadlock: unresolved deps, unsupported requirements, or no capable node.
            for unit_id in sorted(pending):
                req = self._requirements_for(units[unit_id])
                can_fit_any = any(
                    n.total_cpu_units >= req.cpu_units and n.total_memory_bytes >= req.memory_bytes
                    for n in nodes
                )
                reason = "no_capable_node_for_requirements" if not can_fit_any else "dependency_cycle_or_unresolved"
                final_results[unit_id] = {
                    "unit_id": unit_id,
                    "status": STATUS_UNASSIGNED,
                    "dependency_ids": [str(x) for x in units[unit_id].get("dependency_ids", [])],
                    "validation_reasons": [reason],
                    "attempts": attempts[unit_id],
                }
            pending.clear()

        results = [final_results[k] for k in sorted(final_results.keys())]
        return {
            "results": results,
            "assignments": assignment_log,
            "nodes": [n.snapshot() for n in nodes],
            "summary": {
                "total_units": len(results),
                "success": sum(1 for r in results if r.get("status") == STATUS_SUCCESS),
                "failed": sum(1 for r in results if r.get("status") in {STATUS_FAILED, STATUS_TIMEOUT}),
                "blocked_unsafe": sum(1 for r in results if r.get("status") == STATUS_BLOCKED_UNSAFE),
                "unassigned": sum(1 for r in results if r.get("status") == STATUS_UNASSIGNED),
                "skipped_dependency": sum(1 for r in results if r.get("status") == STATUS_SKIPPED_DEPENDENCY),
            },
        }

    @staticmethod
    def _deps_satisfied(
        unit_id: str,
        *,
        units: dict[str, dict[str, Any]],
        results: dict[str, dict[str, Any]],
    ) -> bool:
        deps = [str(x) for x in units[unit_id].get("dependency_ids", [])]
        return all(d in results for d in deps)

    @staticmethod
    def _requirements_for(unit: dict[str, Any]) -> UnitRequirements:
        req = unit.get("resource_requirements", {})
        if isinstance(req, dict):
            cpu = int(req.get("cpu_units", 1))
            mem = int(req.get("memory_bytes", 64 * 1024 * 1024))
            return UnitRequirements(cpu_units=max(1, cpu), memory_bytes=max(1, mem))

        static = unit.get("static_analysis", {})
        if isinstance(static, dict):
            cpu = 1
            mem = 64 * 1024 * 1024
            if static.get("dynamic_execution_primitives"):
                cpu = 2
            if static.get("subprocess_calls"):
                mem = 96 * 1024 * 1024
            return UnitRequirements(cpu_units=cpu, memory_bytes=mem)

        return UnitRequirements()

    @staticmethod
    def _select_node(*, nodes: list[VolunteerNode], requirements: UnitRequirements) -> VolunteerNode | None:
        candidates = [
            n
            for n in nodes
            if n.can_run(cpu_units=requirements.cpu_units, memory_bytes=requirements.memory_bytes)
        ]
        if not candidates:
            return None

        # Prefer tighter memory fit to reserve larger nodes for heavy tasks.
        return sorted(
            candidates,
            key=lambda n: (
                n.available_memory_bytes - requirements.memory_bytes,
                n.available_cpu_units - requirements.cpu_units,
                n.running_tasks,
                n.node_id,
            ),
        )[0]


__all__ = [
    "DistributedTaskScheduler",
    "LocalSandboxExecutor",
    "STATUS_BLOCKED_UNSAFE",
    "STATUS_UNASSIGNED",
    "UnitRequirements",
    "VolunteerNode",
]
