"""
core.autoresearch - Autonomous FP/detection optimization loop.

Inspired by autoresearch patterns: modify-measure-keep/discard loops
that tune scan pipeline parameters to maximize scan quality (AQS)
across a known APK corpus with self-calibrating baselines.

Primary tuning target: artifacts/ml_thresholds.json
"""

__version__ = "0.1.0"

from .config import ExperimentConfig, ParameterBounds, TIER_1_PARAMS, TIER_2_PARAMS, TIER_3_PARAMS
from .metrics import ScanResult, CorpusResult, SessionBaseline, compute_aqs, parse_report
from .parameter_space import snapshot_current, apply_params, revert_to, extract_current_values
from .safety import create_backup, restore_backup, validate_params, install_signal_handler
from .runner import run_corpus, APK_CORPUS
from .history import ExperimentHistory
from .grid_search import coordinate_descent, random_neighbor
from .experiment_loop import run_experiment_loop

__all__ = [
    "ExperimentConfig",
    "ParameterBounds",
    "TIER_1_PARAMS",
    "TIER_2_PARAMS",
    "TIER_3_PARAMS",
    "ScanResult",
    "CorpusResult",
    "SessionBaseline",
    "compute_aqs",
    "parse_report",
    "snapshot_current",
    "apply_params",
    "revert_to",
    "extract_current_values",
    "create_backup",
    "restore_backup",
    "validate_params",
    "install_signal_handler",
    "run_corpus",
    "APK_CORPUS",
    "ExperimentHistory",
    "coordinate_descent",
    "random_neighbor",
    "run_experiment_loop",
]
