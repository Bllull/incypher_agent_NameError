"""Small contract separating challenge orchestration from solver internals."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


SolveChallenge = Callable[[int], str | None]
ProgressSnapshot = Callable[[int], Mapping[str, Any]]


@dataclass(frozen=True)
class SolverBinding:
    """The side-effecting solve operation and its read-only evidence view."""

    solve: SolveChallenge
    progress: ProgressSnapshot
