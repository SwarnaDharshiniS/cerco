"""Tests for sandbox.distributed_scheduler."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sandbox.distributed_scheduler import (
    DistributedTaskScheduler,
    STATUS_BLOCKED_UNSAFE,
    STATUS_UNASSIGNED,
    VolunteerNode,
)
from sandbox.execution_orchestrator import STATUS_FAILED, STATUS_SUCCESS, STATUS_TIMEOUT


class _FakeValidator:
    def __init__(self, unsafe_ids: set[str] | None = None) -> None:
        self._unsafe_ids = unsafe_ids or set()

    def validate(self, unit: dict):
        unit_id = str(unit.get("unit_id"))
        if unit_id in self._unsafe_ids:
            return False, ["unsafe_by_policy"], {"source": "test"}
        return True, [], {"source": "test"}


class _FakeExecutor:
    def __init__(self, scripted_statuses: dict[str, list[str]] | None = None) -> None:
        self._scripted = {k: list(v) for k, v in (scripted_statuses or {}).items()}
        self.calls: list[tuple[str, str]] = []

    def execute(self, *, node: VolunteerNode, unit: dict):
        unit_id = str(unit.get("unit_id"))
        self.calls.append((node.node_id, unit_id))
        queue = self._scripted.get(unit_id, [])
        status = queue.pop(0) if queue else STATUS_SUCCESS
        return {
            "unit_id": unit_id,
            "status": status,
            "stdout": f"ran:{unit_id}",
            "stderr": "",
            "runtime_metadata": {"node_id": node.node_id},
        }


class TestDistributedScheduler(unittest.TestCase):

    def test_assigns_units_to_nodes_with_resource_constraints(self):
        nodes = [
            VolunteerNode(node_id="small", total_cpu_units=1, total_memory_bytes=64 * 1024 * 1024),
            VolunteerNode(node_id="large", total_cpu_units=4, total_memory_bytes=512 * 1024 * 1024),
        ]
        executor = _FakeExecutor()
        scheduler = DistributedTaskScheduler(validator=_FakeValidator(), executor=executor)

        out = scheduler.schedule(
            execution_units=[
                {
                    "unit_id": "light",
                    "code": "print('x')",
                    "resource_requirements": {"cpu_units": 1, "memory_bytes": 32 * 1024 * 1024},
                },
                {
                    "unit_id": "heavy",
                    "code": "print('y')",
                    "resource_requirements": {"cpu_units": 2, "memory_bytes": 256 * 1024 * 1024},
                },
            ],
            nodes=nodes,
        )

        by_unit = {r["unit_id"]: r for r in out["results"]}
        self.assertEqual(by_unit["light"]["status"], STATUS_SUCCESS)
        self.assertEqual(by_unit["heavy"]["status"], STATUS_SUCCESS)
        # heavy must land on large node due to requirements
        heavy_assignment = [a for a in out["assignments"] if a["unit_id"] == "heavy"][0]
        self.assertEqual(heavy_assignment["node_id"], "large")

    def test_blocks_unsafe_units_before_assignment(self):
        nodes = [VolunteerNode(node_id="n1", total_cpu_units=2, total_memory_bytes=128 * 1024 * 1024)]
        executor = _FakeExecutor()
        scheduler = DistributedTaskScheduler(validator=_FakeValidator(unsafe_ids={"u1"}), executor=executor)

        out = scheduler.schedule(execution_units=[{"unit_id": "u1", "code": "eval('1+1')"}], nodes=nodes)
        self.assertEqual(out["results"][0]["status"], STATUS_BLOCKED_UNSAFE)
        self.assertEqual(executor.calls, [])

    def test_retries_failed_units(self):
        nodes = [VolunteerNode(node_id="n1", total_cpu_units=2, total_memory_bytes=128 * 1024 * 1024)]
        executor = _FakeExecutor(scripted_statuses={"u1": [STATUS_FAILED, STATUS_SUCCESS]})
        scheduler = DistributedTaskScheduler(validator=_FakeValidator(), executor=executor, max_retries=1)

        out = scheduler.schedule(execution_units=[{"unit_id": "u1", "code": "print('ok')"}], nodes=nodes)
        self.assertEqual(out["results"][0]["status"], STATUS_SUCCESS)
        self.assertEqual(out["results"][0]["attempts"], 2)

    def test_marks_unassigned_when_no_capable_node(self):
        nodes = [VolunteerNode(node_id="tiny", total_cpu_units=1, total_memory_bytes=32 * 1024 * 1024)]
        scheduler = DistributedTaskScheduler(validator=_FakeValidator(), executor=_FakeExecutor())

        out = scheduler.schedule(
            execution_units=[
                {
                    "unit_id": "big",
                    "code": "print('big')",
                    "resource_requirements": {"cpu_units": 2, "memory_bytes": 256 * 1024 * 1024},
                }
            ],
            nodes=nodes,
        )
        self.assertEqual(out["results"][0]["status"], STATUS_UNASSIGNED)

    def test_dependency_failure_skips_downstream(self):
        nodes = [VolunteerNode(node_id="n1", total_cpu_units=2, total_memory_bytes=128 * 1024 * 1024)]
        executor = _FakeExecutor(scripted_statuses={"a": [STATUS_TIMEOUT]})
        scheduler = DistributedTaskScheduler(validator=_FakeValidator(), executor=executor, max_retries=0)

        out = scheduler.schedule(
            execution_units=[
                {"unit_id": "a", "code": "print('a')"},
                {"unit_id": "b", "code": "print('b')", "dependency_ids": ["a"]},
            ],
            nodes=nodes,
        )
        by_unit = {r["unit_id"]: r for r in out["results"]}
        self.assertEqual(by_unit["a"]["status"], STATUS_TIMEOUT)
        self.assertEqual(by_unit["b"]["status"], "SKIPPED_DEPENDENCY")


if __name__ == "__main__":
    unittest.main()
