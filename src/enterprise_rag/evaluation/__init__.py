"""Evaluation package: golden datasets, offline metrics, Ragas, red team."""

from enterprise_rag.evaluation.dataset import (
    QUALITY_CASES,
    SECURITY_CASES,
    QualityCase,
    SecurityCase,
)
from enterprise_rag.evaluation.metrics import MetricRow, ScoreCard, aggregate, score_case
from enterprise_rag.evaluation.rag_eval import run_offline, run_quality, run_ragas, save_report
from enterprise_rag.evaluation.red_team import ProbeResult, RedTeamReport, run_red_team

__all__ = [
    "MetricRow",
    "ProbeResult",
    "QualityCase",
    "QUALITY_CASES",
    "RedTeamReport",
    "SECURITY_CASES",
    "ScoreCard",
    "SecurityCase",
    "aggregate",
    "run_offline",
    "run_quality",
    "run_ragas",
    "run_red_team",
    "save_report",
    "score_case",
]
