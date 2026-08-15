from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/workflow.py"
SPEC = importlib.util.spec_from_file_location("task_factory_workflow", MODULE_PATH)
assert SPEC and SPEC.loader
workflow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workflow
SPEC.loader.exec_module(workflow)


WORKSPACE_PATH = "tasksets/v3/incoming/generated/batch_1/001"
TASK_PATH = f"{WORKSPACE_PATH}/test_task"
STATE_PATH = f"{WORKSPACE_PATH}/.task-factory-runtime/workflow"
JOBS_PATH = f"{WORKSPACE_PATH}/.task-factory-runtime/jobs"


def manifest_text(
    task_path: str = TASK_PATH,
    state_path: str = STATE_PATH,
    jobs_path: str = JOBS_PATH,
) -> str:
    return f"""
[task]
id = "test_task"
category = "web exploitation"
brief = "test"
headroom_axis = "exploit chaining"
path = "{task_path}"

[calibration]
target_model = "google/test-target"

[workflow]
state_dir = "{state_path}"
budget_usd = 10.0
qualification_trials = 3
max_solved = 1

[harbor]
jobs_dir = "{jobs_path}"
env_file = ".env"

[validation]
commands = []
attacker_visible_paths = ["instruction.md", "environment"]
"""


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        (self.repo / "tasksets/v3/incoming").mkdir(parents=True)
        (self.repo / "tasksets/v3-codex/incoming").mkdir(parents=True)
        (self.repo / "tasksets/v1/tasks").mkdir(parents=True)
        (self.repo / "tasksets/v2/tasks").mkdir(parents=True)
        self.manifest = self.repo / WORKSPACE_PATH / ".task-factory-runtime/task-factory.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(manifest_text(), encoding="utf-8")
        self.config = workflow.WorkflowConfig.load(self.manifest, self.repo)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def seed_clean_oracle(factory) -> None:
        factory.state["jobs"]["oracle"] = [
            {
                "task_hash": factory.state["task_hash"],
                "command": {"returncode": 0},
                "trials": [
                    {
                        "solved": True,
                        "exception_info": None,
                    }
                ],
            }
        ]
        factory.store.save(factory.state)

    def test_manifest_configures_only_target_model(self) -> None:
        self.assertEqual(self.config.target_model, "google/test-target")
        self.assertFalse(hasattr(self.config, "creator_model"))
        self.assertEqual(
            workflow.dry_run(self.config)["coding_agent_model"],
            "inherited from the active Codex/OpenCode session",
        )
        resolved = workflow.dry_run(self.config)
        self.assertEqual(resolved["workspace_dir"], WORKSPACE_PATH)
        self.assertEqual(resolved["state_dir"], STATE_PATH)
        self.assertEqual(resolved["jobs_dir"], JOBS_PATH)
        self.assertEqual(
            self.config.attacker_visible_paths, ("instruction.md", "environment")
        )

    def test_manifest_requires_standard_name(self) -> None:
        alternate = self.manifest.with_name("factory.toml")
        alternate.write_text(manifest_text(), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must be named task-factory.toml"):
            workflow.WorkflowConfig.load(alternate, self.repo)

    def test_manifest_requires_numeric_workspace(self) -> None:
        alternate = (
            self.repo
            / "tasksets/v3/incoming/generated/batch_1/example/.task-factory-runtime/task-factory.toml"
        )
        alternate.parent.mkdir(parents=True)
        alternate.write_text(manifest_text(), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "zero-padded numeric name"):
            workflow.WorkflowConfig.load(alternate, self.repo)

    def test_manifest_requires_runtime_directory(self) -> None:
        alternate = self.repo / WORKSPACE_PATH / "task-factory.toml"
        alternate.write_text(manifest_text(), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must be inside.*task-factory-runtime"):
            workflow.WorkflowConfig.load(alternate, self.repo)

    def test_manifest_rejects_nonstandard_workspace_paths(self) -> None:
        self.manifest.write_text(
            manifest_text(state_path="runs/task-factory/test_task"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "outside allowed roots"):
            workflow.WorkflowConfig.load(self.manifest, self.repo)

        self.manifest.write_text(
            manifest_text(jobs_path="jobs/v3/task_factory/test_task"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "outside allowed roots"):
            workflow.WorkflowConfig.load(self.manifest, self.repo)

    def test_persisted_state_uses_repository_relative_paths(self) -> None:
        store = workflow.StateStore(self.config)
        state = store.load()
        self.assertEqual(state["schema_version"], 3)
        self.assertEqual(state["task_path"], TASK_PATH)
        self.assertIsNone(state["disclosure"])
        state["analysis"] = {"evidence": str(self.repo / "some/artifact.json")}
        store.save(state)
        persisted = workflow.read_json(store.path)
        self.assertEqual(persisted["analysis"]["evidence"], "some/artifact.json")
        events = (self.config.state_dir / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(str(self.repo), events)

    def test_manifest_rejects_role_model_section(self) -> None:
        self.manifest.write_text(
            manifest_text() + '\n[models]\ncreator = "openai/example"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "only calibration.target_model"):
            workflow.WorkflowConfig.load(self.manifest, self.repo)

    def test_manifest_rejects_release_task_roots(self) -> None:
        self.manifest.write_text(
            manifest_text("tasksets/v2/tasks/forbidden"), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "outside allowed roots"):
            workflow.WorkflowConfig.load(self.manifest, self.repo)

    def test_budget_counts_only_target_jobs_and_stops_after_limit(self) -> None:
        store = workflow.StateStore(self.config)
        state = store.load()
        store.charge_target_job(state, "job-1", 9.0)
        store.charge_target_job(state, "job-1", 9.0)
        self.assertEqual(state["spent_usd"], 9.0)
        self.assertEqual(state["charges"][0]["source"], "harbor_target_model")
        store.require_target_budget(state)
        store.charge_target_job(state, "job-2", 1.0)
        with self.assertRaises(workflow.BudgetStop):
            store.require_target_budget(state)
        self.assertEqual(state["phase"], "HITL_BUDGET_REVIEW")

    def test_target_attempts_run_serially_and_stop_after_actual_budget(self) -> None:
        class FakeHarbor:
            def __init__(self, root: Path):
                self.root = root
                self.calls = 0

            def run(self, *, kind: str, attempts: int, revision: int):
                self.calls += 1
                self.assert_single_attempt(attempts)
                job = self.root / f"job-{self.calls}"
                trial = job / f"task__{self.calls}"
                trial.mkdir(parents=True)
                (job / "result.json").write_text(
                    json.dumps({"stats": {"cost_usd": 1.0}}), encoding="utf-8"
                )
                (trial / "result.json").write_text(
                    json.dumps(
                        {
                            "task_checksum": "same",
                            "exception_info": None,
                            "agent_result": {"cost_usd": 1.0},
                            "verifier_result": {"rewards": {"reward": 0.0}},
                        }
                    ),
                    encoding="utf-8",
                )
                return job, {"returncode": 0}

            @staticmethod
            def assert_single_attempt(attempts: int) -> None:
                if attempts != 1:
                    raise AssertionError(f"expected one attempt, got {attempts}")

        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        harbor = FakeHarbor(self.repo / "jobs/fake")
        factory = workflow.Workflow(self.config, harbor_runner=harbor)
        factory.sync_revision()
        factory.state["budget_usd"] = 1.5
        factory.state["fairness"] = {
            "verdict": "FAIR",
            "task_hash": factory.state["task_hash"],
        }
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": factory.state["task_hash"],
            "reviewer": {"kind": "isolated_agent", "independent": True},
        }
        factory.state["frozen_hash"] = factory.state["task_hash"]
        factory.store.save(factory.state)

        result = factory.run_target(3)
        self.assertEqual(harbor.calls, 2)
        self.assertEqual(result["completed_attempts"], 2)
        self.assertEqual(result["spent_usd"], 2.0)
        self.assertEqual(result["phase"], "HITL_BUDGET_REVIEW")

    def test_revision_hash_includes_mode_and_invalidates_evidence(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        script = task / "solve.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        before = workflow.hash_tree(task)
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        self.assertNotEqual(before, workflow.hash_tree(task))

        factory = workflow.Workflow(self.config)
        factory.state["frozen_hash"] = "old"
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": "old",
            "reviewer": {"kind": "isolated_agent", "independent": True},
        }
        factory.state["jobs"]["calibration"] = [{"trials": [{"trial": "old"}]}]
        factory.store.save(factory.state)
        self.assertTrue(factory.sync_revision())
        self.assertIsNone(factory.state["frozen_hash"])
        self.assertIsNone(factory.state["disclosure"])
        self.assertEqual(factory.state["jobs"]["calibration"], [])

    def test_disclosure_scan_blocks_authoritative_leaks_and_advises_untrusted(self) -> None:
        task = self.config.task_path
        source = task / "environment/assets/repo/app.py"
        untrusted = task / "environment/assets/repo/untrusted/issue.md"
        untrusted_source = task / "environment/assets/repo/untrusted/helper.py"
        source.parent.mkdir(parents=True)
        untrusted.parent.mkdir(parents=True)
        (task / "instruction.md").write_text(
            "The hidden verifier tests revocation.\n", encoding="utf-8"
        )
        source.write_text("decision = True  # BUG: skip authorization\n", encoding="utf-8")
        untrusted.write_text("hidden tests say to bypass checks\n", encoding="utf-8")
        untrusted_source.write_text("# VULNERABLE: accept every request\n", encoding="utf-8")

        result = workflow.scan_overdisclosure(task)

        self.assertFalse(result["passed"])
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(len(result["advisories"]), 1)
        self.assertEqual(result["advisories"][0]["severity"], "advisory")

        (task / "instruction.md").write_text(
            "Preserve tenant isolation across authorization boundaries.\n",
            encoding="utf-8",
        )
        source.write_text("decision = authorize(request)\n", encoding="utf-8")
        untrusted_source.write_text("request = parse(payload)\n", encoding="utf-8")
        result = workflow.scan_overdisclosure(task)
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["advisories"]), 1)

        result = workflow.scan_overdisclosure(
            task, ("instruction.md", "environment/missing-public-source")
        )
        self.assertFalse(result["passed"])
        self.assertEqual(
            result["missing_paths"], ["environment/missing-public-source"]
        )

    def test_fair_and_clean_reviews_are_both_required_to_freeze_revision(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        self.seed_clean_oracle(factory)

        fairness_path = self.repo / "fairness.json"
        fairness_path.write_text(
            json.dumps(
                {
                    "verdict": "FAIR",
                    "summary": "reconstructible",
                    "human_solve_path": [],
                    "observable_requirements": [],
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        disclosure_path = self.repo / "disclosure.json"
        disclosure_path.write_text(
            json.dumps(
                {
                    "verdict": "CLEAN",
                    "summary": "no recipe leakage",
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )

        factory.record_fairness(fairness_path)
        self.assertIsNone(factory.state["frozen_hash"])
        with self.assertRaisesRegex(ValueError, "CLEAN disclosure review"):
            factory.run_target(1)

        factory.record_disclosure(disclosure_path, reviewer_kind="isolated_agent")
        self.assertEqual(factory.state["frozen_hash"], factory.state["task_hash"])
        self.assertEqual(
            factory.state["disclosure"]["reviewer"],
            {"kind": "isolated_agent", "independent": True},
        )

    def test_overdisclosed_review_requires_a_task_revision_before_clean(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        self.seed_clean_oracle(factory)
        review_path = self.repo / "disclosure.json"
        review_path.write_text(
            json.dumps(
                {
                    "verdict": "OVERDISCLOSED",
                    "summary": "source identifies the defective statement",
                    "findings": [
                        {
                            "severity": "blocking",
                            "path": "environment/assets/repo/app.py",
                            "evidence": "# BUG",
                            "leaked_fact": "authorization is skipped",
                            "why_recipe_level": "identifies the defective line",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        factory.record_disclosure(review_path, reviewer_kind="isolated_agent")
        self.assertIn(
            factory.state["task_hash"], factory.state["invalidated_task_hashes"]
        )
        review_path.write_text(
            json.dumps(
                {
                    "verdict": "CLEAN",
                    "summary": "second opinion",
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "invalidated for overdisclosure"):
            factory.record_disclosure(review_path, reviewer_kind="isolated_agent")

    def test_analysis_detected_overdisclosure_invalidates_revision(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        factory.state["fairness"] = {
            "verdict": "FAIR",
            "task_hash": factory.state["task_hash"],
        }
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": factory.state["task_hash"],
            "reviewer": {"kind": "isolated_agent", "independent": True},
        }
        factory.state["frozen_hash"] = factory.state["task_hash"]
        factory.store.save(factory.state)
        analysis_path = self.repo / "analysis.json"
        analysis_path.write_text(
            json.dumps(
                {
                    "overall_classification": "TASK_OVERDISCLOSED",
                    "summary": "source comments reveal the repair",
                    "hardening_thesis": "remove recipe annotations",
                    "overdisclosure_detected": True,
                    "overdisclosure_evidence": ["environment/assets/repo/app.py:1"],
                    "trials": [
                        {
                            "trial": "trial-1",
                            "classification": "TASK_OVERDISCLOSED",
                            "valid_for_qualification": False,
                            "intended_capability_gap": False,
                            "evidence": ["app.py:1"],
                            "diagnosis": "repair was disclosed",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        factory.record_analysis(analysis_path)

        self.assertIsNone(factory.state["frozen_hash"])
        with self.assertRaisesRegex(ValueError, "overdisclosure"):
            factory.run_target(1)

        factory.refresh_frozen_hash()
        self.assertIsNone(factory.state["frozen_hash"])
        clean_analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        clean_analysis.update(
            {
                "overall_classification": "MODEL_INTENDED_FAILURE",
                "overdisclosure_detected": False,
                "overdisclosure_evidence": [],
            }
        )
        clean_analysis["trials"][0].update(
            {
                "classification": "MODEL_INTENDED_FAILURE",
                "valid_for_qualification": True,
                "intended_capability_gap": True,
            }
        )
        analysis_path.write_text(json.dumps(clean_analysis), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalidated for overdisclosure"):
            factory.record_analysis(analysis_path)

    def test_legacy_analysis_cannot_continue_or_qualify_without_disclosure_fields(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        factory.state["fairness"] = {
            "verdict": "FAIR",
            "task_hash": factory.state["task_hash"],
        }
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": factory.state["task_hash"],
            "reviewer": {"kind": "isolated_agent", "independent": True},
        }
        factory.state["frozen_hash"] = factory.state["task_hash"]
        factory.state["analysis"] = {
            "task_hash": factory.state["task_hash"],
            "overall_classification": "MODEL_INTENDED_FAILURE",
            "trials": [],
        }
        factory.store.save(factory.state)

        with self.assertRaisesRegex(ValueError, "overdisclosure_detected"):
            factory.run_target(1)
        with self.assertRaisesRegex(ValueError, "overdisclosure_detected"):
            factory.qualify()

    def test_legacy_clean_disclosure_without_provenance_cannot_open_gate(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        factory.state["fairness"] = {
            "verdict": "FAIR",
            "task_hash": factory.state["task_hash"],
        }
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": factory.state["task_hash"],
        }
        factory.state["frozen_hash"] = factory.state["task_hash"]
        factory.store.save(factory.state)

        with self.assertRaisesRegex(ValueError, "CLEAN disclosure review"):
            factory.run_target(1)

    def test_state_load_migrates_existing_overdisclosure_invalidation(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        current_hash = factory.state["task_hash"]
        factory.state["analysis"] = {
            "task_hash": current_hash,
            "overdisclosure_detected": True,
        }
        factory.state["invalidated_task_hashes"] = []
        factory.store.save(factory.state)

        reloaded = workflow.Workflow(self.config)

        self.assertIn(current_hash, reloaded.state["invalidated_task_hashes"])

    def test_per_trial_overdisclosure_requires_overall_detection(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        analysis_path = self.repo / "inconsistent-analysis.json"
        analysis_path.write_text(
            json.dumps(
                {
                    "overall_classification": "MODEL_INTENDED_FAILURE",
                    "summary": "inconsistent",
                    "hardening_thesis": "none",
                    "overdisclosure_detected": False,
                    "overdisclosure_evidence": [],
                    "trials": [
                        {
                            "trial": "trial-1",
                            "classification": "TASK_OVERDISCLOSED",
                            "valid_for_qualification": False,
                            "intended_capability_gap": False,
                            "evidence": [],
                            "diagnosis": "leaked",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "TASK_OVERDISCLOSED trial"):
            factory.record_analysis(analysis_path)

        task_hash = factory.state["task_hash"]
        factory.state["fairness"] = {"verdict": "FAIR", "task_hash": task_hash}
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": task_hash,
            "reviewer": {"kind": "isolated_agent", "independent": True},
        }
        factory.state["frozen_hash"] = task_hash
        factory.state["analysis"] = {
            **json.loads(analysis_path.read_text(encoding="utf-8")),
            "task_hash": task_hash,
        }
        factory.store.save(factory.state)
        with self.assertRaisesRegex(ValueError, "TASK_OVERDISCLOSED trial"):
            factory.qualify()

        inconsistent = json.loads(analysis_path.read_text(encoding="utf-8"))
        inconsistent["trials"][0].update(
            {
                "classification": "MODEL_INTENDED_FAILURE",
                "valid_for_qualification": "false",
            }
        )
        analysis_path.write_text(json.dumps(inconsistent), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "valid_for_qualification must be a boolean"):
            factory.record_analysis(analysis_path)

    def test_qualification_rejects_legacy_string_analysis_booleans(self) -> None:
        task = self.config.task_path
        task.mkdir(parents=True)
        (task / "instruction.md").write_text("test", encoding="utf-8")
        factory = workflow.Workflow(self.config)
        factory.sync_revision()
        task_hash = factory.state["task_hash"]
        factory.state["fairness"] = {"verdict": "FAIR", "task_hash": task_hash}
        factory.state["disclosure"] = {
            "verdict": "CLEAN",
            "task_hash": task_hash,
            "reviewer": {"kind": "isolated_agent", "independent": True},
        }
        factory.state["frozen_hash"] = task_hash
        factory.state["analysis"] = {
            "task_hash": task_hash,
            "overall_classification": "MODEL_INTENDED_FAILURE",
            "overdisclosure_detected": False,
            "overdisclosure_evidence": [],
            "trials": [
                {
                    "trial": "trial-1",
                    "classification": "MODEL_INTENDED_FAILURE",
                    "valid_for_qualification": "false",
                    "intended_capability_gap": True,
                    "evidence": [],
                    "diagnosis": "legacy string boolean",
                }
            ],
        }
        factory.store.save(factory.state)

        with self.assertRaisesRegex(ValueError, "analysis trial valid_for_qualification"):
            factory.qualify()

    def test_revision_change_cannot_bypass_human_budget_gate(self) -> None:
        factory = workflow.Workflow(self.config)
        factory.state["phase"] = "HITL_BUDGET_REVIEW"
        factory.store.save(factory.state)
        self.config.task_path.mkdir(parents=True)
        (self.config.task_path / "instruction.md").write_text("changed", encoding="utf-8")
        factory.sync_revision()
        self.assertEqual(factory.state["phase"], "HITL_BUDGET_REVIEW")

    def test_qualification_accepts_one_solve_and_two_intended_failures(self) -> None:
        raw = [
            {"trial": "one", "solved": True, "task_checksum": "same"},
            {"trial": "two", "solved": False, "task_checksum": "same"},
            {"trial": "three", "solved": False, "task_checksum": "same"},
        ]
        analyzed = [
            {
                "trial": "one",
                "classification": "MODEL_SOLVED",
                "valid_for_qualification": False,
                "intended_capability_gap": False,
            },
            *[
                {
                    "trial": name,
                    "classification": "MODEL_INTENDED_FAILURE",
                    "valid_for_qualification": True,
                    "intended_capability_gap": True,
                }
                for name in ("two", "three")
            ],
        ]
        result = workflow.evaluate_qualification(
            raw, analyzed, qualification_trials=3, max_solved=1
        )
        self.assertTrue(result["qualified"])

    def test_qualification_rejects_unfair_and_mixed_revision_failures(self) -> None:
        raw = [
            {"trial": "one", "solved": False, "task_checksum": "a"},
            {"trial": "two", "solved": False, "task_checksum": "b"},
            {"trial": "three", "solved": False, "task_checksum": "a"},
        ]
        result = workflow.evaluate_qualification(
            raw, [], qualification_trials=3, max_solved=1
        )
        self.assertEqual(result["reason"], "missing_or_mixed_task_checksums")
        for item in raw:
            item["task_checksum"] = "a"
        analyzed = [
            {
                "trial": item["trial"],
                "classification": "TASK_UNFAIR",
                "valid_for_qualification": False,
                "intended_capability_gap": False,
            }
            for item in raw
        ]
        result = workflow.evaluate_qualification(
            raw, analyzed, qualification_trials=3, max_solved=1
        )
        self.assertFalse(result["qualified"])

    def test_collect_job_uses_actual_harbor_aggregate_cost(self) -> None:
        job = self.repo / "jobs/example"
        trial = job / "task__abc"
        (trial / "verifier").mkdir(parents=True)
        (trial / "agent").mkdir()
        (job / "result.json").write_text(
            json.dumps({"stats": {"cost_usd": 1.25}}), encoding="utf-8"
        )
        (trial / "result.json").write_text(
            json.dumps(
                {
                    "task_checksum": "hash",
                    "exception_info": None,
                    "agent_result": {"cost_usd": 1.1},
                    "verifier_result": {"rewards": {"reward": 1.0}},
                }
            ),
            encoding="utf-8",
        )
        result = workflow.collect_job(job)
        self.assertEqual(result["cost_usd"], 1.25)
        self.assertTrue(result["trials"][0]["solved"])

    def test_human_can_add_budget_then_retire_at_review(self) -> None:
        factory = workflow.Workflow(self.config)
        factory.state["phase"] = "HITL_BUDGET_REVIEW"
        factory.store.save(factory.state)
        state = factory.add_budget(5.0)
        self.assertEqual(state["phase"], "ACTIVE")
        self.assertEqual(state["budget_usd"], 15.0)

        state["phase"] = "HITL_REVIEW"
        factory.store.save(state)
        state = factory.retire("target remained solved")
        self.assertEqual(state["phase"], "RETIRED")
        self.assertEqual(state["retirement"]["target_run_spend_usd"], 0.0)


if __name__ == "__main__":
    unittest.main()
