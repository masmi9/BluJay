"""
core.autoresearch.grid_search - Parameter generation strategies (no LLM).

Provides coordinate descent and random neighbor generation for
the experiment loop's grid and random modes.
"""

from __future__ import annotations

import random as _random
from typing import Dict, Iterator, List

from .config import ParameterBounds


def coordinate_descent(
    current_best: Dict[str, float],
    bounds: List[ParameterBounds],
    step: float = 0.0,
) -> Iterator[Dict[str, float]]:
    """Generate candidates by varying one parameter at a time across its range.

    For each parameter, yields candidates at each step value while keeping
    other parameters at their current best values.

    Args:
        current_best: Current best parameter values.
        bounds: Parameter definitions with bounds and steps.
        step: Override step size (0 = use per-param step).

    Yields:
        Dict of parameter name -> value for each candidate.
    """
    for param in bounds:
        param_step = step if step > 0 else param.step
        current_val = current_best.get(param.name, param.default_value)

        # Generate values across the range
        val = param.min_value
        while val <= param.max_value + 1e-9:
            rounded = round(val, 4)
            # Skip if same as current value (within tolerance)
            if abs(rounded - current_val) > 1e-6:
                candidate = dict(current_best)
                candidate[param.name] = rounded
                yield candidate
            val += param_step


def random_neighbor(
    current_best: Dict[str, float],
    bounds: List[ParameterBounds],
    n_mutations: int = 3,
) -> Dict[str, float]:
    """Generate a random neighbor by mutating n_mutations parameters.

    Each mutated parameter is sampled uniformly within its bounds.

    Args:
        current_best: Current best parameter values.
        bounds: Parameter definitions.
        n_mutations: Number of parameters to mutate.

    Returns:
        New parameter dict with n_mutations parameters changed.
    """
    candidate = dict(current_best)
    n = min(n_mutations, len(bounds))
    selected = _random.sample(bounds, n)

    for param in selected:
        # Sample uniformly within bounds, snapped to step grid
        steps = int((param.max_value - param.min_value) / param.step)
        if steps <= 0:
            candidate[param.name] = param.min_value
            continue
        step_idx = _random.randint(0, steps)
        value = param.min_value + step_idx * param.step
        candidate[param.name] = round(min(value, param.max_value), 4)

    return candidate


def random_initial(bounds: List[ParameterBounds]) -> Dict[str, float]:
    """Generate a fully random parameter set within bounds."""
    params: Dict[str, float] = {}
    for param in bounds:
        steps = int((param.max_value - param.min_value) / param.step)
        if steps <= 0:
            params[param.name] = param.min_value
            continue
        step_idx = _random.randint(0, steps)
        value = param.min_value + step_idx * param.step
        params[param.name] = round(min(value, param.max_value), 4)
    return params
