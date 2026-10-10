"""Independent, fixed Linux Audit process-candidate evaluation corpus."""

from dataclasses import dataclass
from pathlib import Path

from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.process_execution import aggregate_process_execution_observations
from app.analyzer.process_execution_classification import (
    CATEGORY_IDS, ProcessExecutionClassificationError,
    classify_process_execution_observations,
)
from app.models.schemas import NormalizedEvent


_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "evaluation"


@dataclass(frozen=True)
class LinuxProcessScenario:
    id: str
    fixture: str
    expected_categories: tuple[str, ...]
    expected_outcome: str
    expected_unclassified_count: int = 0
    expected_incomplete_count: int = 0


LINUX_PROCESS_SCENARIOS = (
    LinuxProcessScenario("linux_shell_bash", "linux_shell_bash.log", (CATEGORY_IDS[0],), "success"),
    LinuxProcessScenario("linux_shell_sh_failure", "linux_shell_sh_failure.log", (CATEGORY_IDS[0],), "failure"),
    LinuxProcessScenario("linux_network_curl", "linux_network_curl.log", (CATEGORY_IDS[1],), "success"),
    LinuxProcessScenario("linux_network_wget_unknown", "linux_network_wget_unknown.log", (CATEGORY_IDS[1],), "unknown"),
    LinuxProcessScenario("linux_permission_chmod", "linux_permission_chmod.log", (CATEGORY_IDS[2],), "success"),
    LinuxProcessScenario("linux_permission_chown", "linux_permission_chown.log", (CATEGORY_IDS[2],), "failure"),
    LinuxProcessScenario("linux_temp_tool", "linux_temp_tool.log", (CATEGORY_IDS[3],), "success"),
    LinuxProcessScenario("linux_temp_curl", "linux_temp_curl.log", (CATEGORY_IDS[1], CATEGORY_IDS[3]), "success"),
    LinuxProcessScenario("linux_normal_tool", "linux_normal_tool.log", (), "success", 1),
    LinuxProcessScenario("linux_conflict_identity", "linux_conflict_identity.log", (), "success", 1),
    LinuxProcessScenario("linux_fallback_comm", "linux_fallback_comm.log", (CATEGORY_IDS[0],), "success"),
    LinuxProcessScenario("linux_shell_bashful", "linux_shell_bashful.log", (), "success", 1),
    LinuxProcessScenario("linux_network_curl_wrapper", "linux_network_curl_wrapper.log", (), "success", 1),
    LinuxProcessScenario("linux_permission_chmodder", "linux_permission_chmodder.log", (), "success", 1),
    LinuxProcessScenario("linux_temp_shm", "linux_temp_shm.log", (CATEGORY_IDS[3],), "failure"),
    LinuxProcessScenario("linux_temp_sibling", "linux_temp_sibling.log", (), "success", 1),
    LinuxProcessScenario("linux_temp_backup_sibling", "linux_temp_backup_sibling.log", (), "success", 1),
    LinuxProcessScenario("linux_cwd_only_temp", "linux_cwd_only_temp.log", (), "success", 1),
    LinuxProcessScenario("linux_incomplete_argv", "linux_incomplete_argv.log", (CATEGORY_IDS[1],), "success", 0, 1),
    LinuxProcessScenario("linux_incomplete_path", "linux_incomplete_path.log", (CATEGORY_IDS[2],), "success", 0, 1),
    LinuxProcessScenario("linux_temp_bash", "linux_temp_bash.log", (CATEGORY_IDS[0], CATEGORY_IDS[3]), "success"),
)


class LinuxProcessEvaluationError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in {"invalid_label", "fixture_unavailable", "analysis_failed"} else "invalid_label"
        super().__init__(self.code)


@dataclass(frozen=True)
class LinuxCategoryMetric:
    category_id: str
    expected_observation_count: int
    actual_observation_count: int
    expected_unique_execution_count: int
    duplicate_observation_count: int
    false_category_assignment: int
    missed_category_assignment: int
    precision: str
    recall: str


@dataclass(frozen=True)
class LinuxProcessEvaluationSummary:
    scenario_count: int
    passed_scenarios: int
    failed_scenarios: int
    category_metrics: tuple[LinuxCategoryMetric, ...]
    outcome_consistency_count: int
    aggregate_consistency_count: int
    invariant_failures: tuple[str, ...]
    interpretation_notices: tuple[str, ...]


def evaluate_linux_process(
    scenarios: tuple[LinuxProcessScenario, ...] = LINUX_PROCESS_SCENARIOS,
) -> LinuxProcessEvaluationSummary:
    if type(scenarios) is not tuple or not scenarios:
        raise LinuxProcessEvaluationError("invalid_label")
    ids = set()
    for scenario in scenarios:
        if (
            type(scenario) is not LinuxProcessScenario
            or type(scenario.id) is not str
            or not scenario.id.startswith("linux_")
            or not scenario.id.isascii()
            or not scenario.id.replace("_", "").isalnum()
            or len(scenario.id) > 64
            or scenario.id in ids
            or type(scenario.fixture) is not str
            or scenario.fixture != scenario.id + ".log"
            or type(scenario.expected_categories) is not tuple
            or any(category not in CATEGORY_IDS for category in scenario.expected_categories)
            or len(set(scenario.expected_categories)) != len(scenario.expected_categories)
            or scenario.expected_outcome not in {"success", "failure", "unknown"}
            or type(scenario.expected_unclassified_count) is not int
            or scenario.expected_unclassified_count not in {0, 1}
            or type(scenario.expected_incomplete_count) is not int
            or scenario.expected_incomplete_count not in {0, 1}
        ):
            raise LinuxProcessEvaluationError("invalid_label")
        ids.add(scenario.id)

    expected_counts = {category: 0 for category in CATEGORY_IDS}
    actual_counts = {category: 0 for category in CATEGORY_IDS}
    false_counts = {category: 0 for category in CATEGORY_IDS}
    missed_counts = {category: 0 for category in CATEGORY_IDS}
    duplicate_counts = {category: 0 for category in CATEGORY_IDS}
    failures = []
    outcome_consistency = 0
    aggregate_consistency = 0
    for scenario in scenarios:
        path = _ROOT / scenario.fixture
        try:
            valid_fixture = not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= 4096
        except OSError:
            valid_fixture = False
        if not valid_fixture:
            raise LinuxProcessEvaluationError("fixture_unavailable")
        try:
            logs = load_normalized_logs([{"source": "linux_audit", "path": str(path),
                                          "source_instance": "evaluation-linux"}])
            process_events = tuple(event for event in logs if type(event) is NormalizedEvent
                                   and event.event_type == "process_execution_attempt")
            if len(process_events) != 1:
                failures.append(scenario.id + ":parser")
                continue
            aggregate = aggregate_process_execution_observations(process_events)
            assembly = classify_process_execution_observations(process_events)
        except (OSError, UnicodeError, ValueError, TypeError, ProcessExecutionClassificationError):
            raise LinuxProcessEvaluationError("analysis_failed") from None
        observed = tuple(item.category_id for item in assembly.observations)
        for category in CATEGORY_IDS:
            expected = int(category in scenario.expected_categories)
            actual = observed.count(category)
            expected_counts[category] += expected
            actual_counts[category] += actual
            false_counts[category] += max(0, actual - expected)
            missed_counts[category] += max(0, expected - actual)
            duplicate_counts[category] += max(0, actual - 1)
        outcome_ok = (process_events[0].process_execution.outcome == scenario.expected_outcome
                      and getattr(assembly.summary.outcome_counts, scenario.expected_outcome) == 1)
        aggregate_ok = (
            aggregate["observation_count"] == assembly.summary.eligible_execution_count == 1
            and aggregate["outcome_counts"] == {
                "success": assembly.summary.outcome_counts.success,
                "failure": assembly.summary.outcome_counts.failure,
                "unknown": assembly.summary.outcome_counts.unknown,
            }
            and assembly.incomplete_context_count == scenario.expected_incomplete_count
        )
        outcome_consistency += int(outcome_ok)
        aggregate_consistency += int(aggregate_ok)
        if (
            tuple(sorted(observed)) != tuple(sorted(scenario.expected_categories))
            or assembly.unclassified_count != scenario.expected_unclassified_count
            or not outcome_ok or not aggregate_ok
        ):
            failures.append(scenario.id + ":classification")
    def ratio(numerator: int, denominator: int) -> str:
        return "not_applicable" if denominator == 0 else f"{numerator / denominator:.6f}"

    metrics = tuple(LinuxCategoryMetric(
        category, expected_counts[category], actual_counts[category],
        expected_counts[category], duplicate_counts[category],
        false_counts[category], missed_counts[category],
        ratio(expected_counts[category] - missed_counts[category], actual_counts[category]),
        ratio(expected_counts[category] - missed_counts[category], expected_counts[category]),
    ) for category in CATEGORY_IDS)
    return LinuxProcessEvaluationSummary(
        len(scenarios), len(scenarios) - len(failures), len(failures), metrics,
        outcome_consistency, aggregate_consistency, tuple(failures),
        (
            "Linux Audit의 합성 실행 문맥에서 고정 분류와 aggregate 일치만 평가합니다.",
            "실제 운영환경의 악성 탐지율, 전송 성공 또는 권한 변경 성공을 의미하지 않습니다.",
        ),
    )
