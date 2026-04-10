"""
core.autoresearch.tools - Agent tools for LLM-guided optimization mode.

Provides 5 tools that the LLM can use to inspect state and propose parameters.
Registered under the "autoresearch" agent type allowlist.
"""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, ConfigDict, Field

from core.agent.tools.base import BaseTool, ToolContext, ToolResult


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

class EmptyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HistoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n: int = Field(default=10, ge=1, le=50, description="Number of recent experiments to return")


class ProposeParamsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    params: Dict[str, float] = Field(description="Parameter name -> proposed value")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

class GetCurrentParams(BaseTool):
    """Returns current parameter values with their bounds."""

    @property
    def name(self) -> str:
        return "get_current_params"

    @property
    def description(self) -> str:
        return (
            "Get current tunable parameter values along with their min/max bounds "
            "and tier. Use this to understand what can be tuned and current state."
        )

    @property
    def InputModel(self):
        return EmptyInput

    def execute(self, input_data: BaseModel, context: ToolContext) -> ToolResult:
        from .config import get_params_for_tiers
        from .parameter_space import extract_current_values

        bounds = get_params_for_tiers([1, 2, 3])
        values = extract_current_values(bounds)

        params_info = []
        for b in bounds:
            params_info.append({
                "name": b.name,
                "current_value": values.get(b.name, b.default_value),
                "min": b.min_value,
                "max": b.max_value,
                "default": b.default_value,
                "step": b.step,
                "tier": b.tier,
            })

        return ToolResult(success=True, data={"parameters": params_info})


class GetExperimentHistory(BaseTool):
    """Returns recent experiment results."""

    @property
    def name(self) -> str:
        return "get_experiment_history"

    @property
    def description(self) -> str:
        return (
            "Get the last N experiments with their AQS scores, parameters, "
            "and accept/reject decisions. Use to identify trends."
        )

    @property
    def InputModel(self):
        return HistoryInput

    def execute(self, input_data: BaseModel, context: ToolContext) -> ToolResult:
        from .history import ExperimentHistory

        history = ExperimentHistory()
        recent = history.get_recent(n=input_data.n)
        history.close()
        return ToolResult(success=True, data={"experiments": recent})


class GetBaselineInfo(BaseTool):
    """Returns the session baseline information."""

    @property
    def name(self) -> str:
        return "get_baseline_info"

    @property
    def description(self) -> str:
        return (
            "Get the session baseline: per-APK finding counts and severity "
            "distributions from the calibration run."
        )

    @property
    def InputModel(self):
        return EmptyInput

    def execute(self, input_data: BaseModel, context: ToolContext) -> ToolResult:
        from .parameter_space import REPO_ROOT

        # Find the most recent run's baseline
        runs_dir = REPO_ROOT / "data" / "autoresearch" / "runs"
        if not runs_dir.exists():
            return ToolResult(success=False, error="No autoresearch runs found")

        run_dirs = sorted(runs_dir.iterdir(), reverse=True)
        for rd in run_dirs:
            bl_path = rd / "baseline.json"
            if bl_path.exists():
                from .metrics import SessionBaseline
                baseline = SessionBaseline.load(bl_path)
                return ToolResult(success=True, data=baseline.to_dict())

        return ToolResult(success=False, error="No baseline found in recent runs")


class GetLatestResults(BaseTool):
    """Returns per-APK breakdown from the most recent experiment."""

    @property
    def name(self) -> str:
        return "get_latest_results"

    @property
    def description(self) -> str:
        return (
            "Get the per-APK findings breakdown from the most recent experiment. "
            "Shows total findings, severity distribution, and scan time per APK."
        )

    @property
    def InputModel(self):
        return EmptyInput

    def execute(self, input_data: BaseModel, context: ToolContext) -> ToolResult:
        from .history import ExperimentHistory

        history = ExperimentHistory()
        recent = history.get_recent(n=1)
        history.close()

        if not recent:
            return ToolResult(success=False, error="No experiments recorded yet")

        exp = recent[0]
        return ToolResult(success=True, data={
            "experiment_num": exp.get("experiment_num"),
            "aqs": exp.get("aqs"),
            "detection_score": exp.get("detection_score"),
            "fp_penalty": exp.get("fp_penalty"),
            "stability_bonus": exp.get("stability_bonus"),
            "accepted": exp.get("accepted"),
            "per_apk": exp.get("per_apk", []),
        })


class ProposeParams(BaseTool):
    """Accepts proposed parameter values, validates, and returns validated params."""

    @property
    def name(self) -> str:
        return "propose_params"

    @property
    def description(self) -> str:
        return (
            "Propose new parameter values for the next experiment. "
            "Provide a dict of parameter_name -> float value. "
            "Only include parameters you want to change. "
            "Values are validated against bounds before acceptance."
        )

    @property
    def InputModel(self):
        return ProposeParamsInput

    def execute(self, input_data: BaseModel, context: ToolContext) -> ToolResult:
        from .config import get_params_for_tiers
        from .parameter_space import extract_current_values
        from .safety import validate_params

        bounds = get_params_for_tiers([1, 2, 3])
        current = extract_current_values(bounds)

        # Merge: start with current, overlay proposed
        merged = dict(current)
        merged.update(input_data.params)

        violations = validate_params(merged, bounds)
        if violations:
            return ToolResult(
                success=False,
                error=f"Validation failed: {'; '.join(violations)}",
                data={"violations": violations},
            )

        return ToolResult(success=True, data={
            "validated_params": merged,
            "changed": {
                k: {"from": current.get(k), "to": v}
                for k, v in merged.items()
                if abs(v - current.get(k, 0)) > 1e-6
            },
        })


# All tools for registration
ALL_TOOLS: List[BaseTool] = [
    GetCurrentParams(),
    GetExperimentHistory(),
    GetBaselineInfo(),
    GetLatestResults(),
    ProposeParams(),
]
