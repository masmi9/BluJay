"""
core.autoresearch.config - Experiment configuration and parameter bounds.

Defines the parameter space (3 tiers) and experiment configuration
using Pydantic V2 models.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ParameterBounds(BaseModel):
    """Defines bounds and metadata for a single tunable parameter."""

    model_config = ConfigDict(extra="forbid")

    name: str
    json_path: str = Field(description="Dot-separated path in ml_thresholds.json or 'env:VAR_NAME'")
    min_value: float
    max_value: float
    default_value: float
    step: float = 0.05
    tier: int = 1


class ExperimentConfig(BaseModel):
    """Configuration for an autoresearch experiment session."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["grid", "random", "llm"] = "random"
    max_experiments: int = Field(default=50, ge=1, le=500)
    max_wall_time_minutes: int = Field(default=120, ge=1, le=720)
    corpus_subset: List[str] = Field(default_factory=list, description="APK names to include (empty = all)")
    scan_profile: str = "standard"
    scan_timeout_seconds: int = Field(default=600, ge=60, le=3600)
    param_tiers: List[int] = Field(default_factory=lambda: [1])
    random_mutations_per_iter: int = Field(default=3, ge=1, le=10)
    max_regression_pct: float = Field(default=10.0, ge=0.0, le=100.0)
    keep_top_n: int = Field(default=5, ge=1, le=50)
    parallel_scans: int = Field(default=2, ge=1, le=4)
    dry_run: bool = False
    fast_proxy: bool = False
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None


# ---------------------------------------------------------------------------
# Tier 1 - Global FP controls (7 params, highest impact)
# ---------------------------------------------------------------------------

TIER_1_PARAMS: List[ParameterBounds] = [
    ParameterBounds(
        name="dampener_range_low",
        json_path="dampening.range.0",
        min_value=0.50,
        max_value=0.85,
        default_value=0.70,
        step=0.05,
        tier=1,
    ),
    ParameterBounds(
        name="dampener_range_high",
        json_path="dampening.range.1",
        min_value=0.70,
        max_value=0.95,
        default_value=0.85,
        step=0.05,
        tier=1,
    ),
    ParameterBounds(
        name="dampener_base_factor",
        json_path="dampening.base_factor",
        min_value=0.05,
        max_value=0.40,
        default_value=0.15,
        step=0.05,
        tier=1,
    ),
    ParameterBounds(
        name="dampener_drop_threshold",
        json_path="dampening.drop_threshold",
        min_value=0.30,
        max_value=0.65,
        default_value=0.50,
        step=0.05,
        tier=1,
    ),
    ParameterBounds(
        name="ml_fp_threshold",
        json_path="env:AODS_ML_FP_THRESHOLD",
        min_value=0.05,
        max_value=0.35,
        default_value=0.15,
        step=0.05,
        tier=1,
    ),
    ParameterBounds(
        name="vuln_app_ml_threshold",
        json_path="yaml:ml_filtering_control.vulnerable_app_ml_filtering_threshold",
        min_value=0.05,
        max_value=0.30,
        default_value=0.15,
        step=0.05,
        tier=1,
    ),
    ParameterBounds(
        name="prod_app_ml_threshold",
        json_path="yaml:ml_filtering_control.production_app_ml_filtering_threshold",
        min_value=0.01,
        max_value=0.15,
        default_value=0.05,
        step=0.02,
        tier=1,
    ),
]

# ---------------------------------------------------------------------------
# Tier 2 - Per-source noise weights (8 params)
# ---------------------------------------------------------------------------

TIER_2_PARAMS: List[ParameterBounds] = [
    ParameterBounds(
        name="noisy_apk_signing",
        json_path="dampening.noisy_plugins.apk_signing_certificate_analyzer",
        min_value=0.0,
        max_value=1.0,
        default_value=0.625,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_ssl_tls",
        json_path="dampening.noisy_plugins.advanced_ssl_tls_analyzer",
        min_value=0.0,
        max_value=1.0,
        default_value=0.583,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_jadx",
        json_path="dampening.noisy_plugins.jadx_static_analysis",
        min_value=0.0,
        max_value=1.0,
        default_value=0.452,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_webview",
        json_path="dampening.noisy_plugins.webview_security_analysis",
        min_value=0.0,
        max_value=1.0,
        default_value=0.368,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_cleartext",
        json_path="dampening.noisy_plugins.network_cleartext_traffic",
        min_value=0.0,
        max_value=1.0,
        default_value=0.341,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_cwe329",
        json_path="dampening.noisy_cwes.CWE-329",
        min_value=0.0,
        max_value=1.0,
        default_value=0.50,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_cwe732",
        json_path="dampening.noisy_cwes.CWE-732",
        min_value=0.0,
        max_value=1.0,
        default_value=0.556,
        step=0.05,
        tier=2,
    ),
    ParameterBounds(
        name="noisy_cwe749",
        json_path="dampening.noisy_cwes.CWE-749",
        min_value=0.0,
        max_value=1.0,
        default_value=0.571,
        step=0.05,
        tier=2,
    ),
]

# ---------------------------------------------------------------------------
# Tier 3 - Per-category detection thresholds (7 params)
# ---------------------------------------------------------------------------

TIER_3_PARAMS: List[ParameterBounds] = [
    ParameterBounds(
        name="cat_crypto",
        json_path="categories.CRYPTO",
        min_value=0.30,
        max_value=0.70,
        default_value=0.55,
        step=0.05,
        tier=3,
    ),
    ParameterBounds(
        name="cat_storage",
        json_path="categories.STORAGE",
        min_value=0.30,
        max_value=0.70,
        default_value=0.50,
        step=0.05,
        tier=3,
    ),
    ParameterBounds(
        name="cat_network",
        json_path="categories.NETWORK",
        min_value=0.30,
        max_value=0.70,
        default_value=0.45,
        step=0.05,
        tier=3,
    ),
    ParameterBounds(
        name="cat_auth",
        json_path="categories.AUTH",
        min_value=0.30,
        max_value=0.70,
        default_value=0.50,
        step=0.05,
        tier=3,
    ),
    ParameterBounds(
        name="cat_code_quality",
        json_path="categories.CODE_QUALITY",
        min_value=0.30,
        max_value=0.70,
        default_value=0.50,
        step=0.05,
        tier=3,
    ),
    ParameterBounds(
        name="cat_platform",
        json_path="categories.PLATFORM",
        min_value=0.30,
        max_value=0.70,
        default_value=0.50,
        step=0.05,
        tier=3,
    ),
    ParameterBounds(
        name="cat_resilience",
        json_path="categories.RESILIENCE",
        min_value=0.30,
        max_value=0.70,
        default_value=0.55,
        step=0.05,
        tier=3,
    ),
]


def get_params_for_tiers(tiers: List[int]) -> List[ParameterBounds]:
    """Return parameter bounds for the requested tiers."""
    all_params = {1: TIER_1_PARAMS, 2: TIER_2_PARAMS, 3: TIER_3_PARAMS}
    result = []
    for t in sorted(set(tiers)):
        result.extend(all_params.get(t, []))
    return result
