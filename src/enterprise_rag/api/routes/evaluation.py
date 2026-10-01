"""Evaluation endpoints: run quality + red-team suites, read previous reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from enterprise_rag.api.deps import ContextDep, require_roles
from enterprise_rag.evaluation.dataset import QUALITY_CASES, SECURITY_CASES
from enterprise_rag.evaluation.rag_eval import run_quality, save_report
from enterprise_rag.evaluation.red_team import run_red_team
from enterprise_rag.security.identity import User

router = APIRouter(prefix="/api/eval", tags=["evaluation"])

Evaluator = Annotated[User, Depends(require_roles("compliance_officer", "platform_admin"))]

SUITES = ("quality", "security", "both")
ENGINES = ("auto", "offline", "ragas")


class EvalRequest(BaseModel):
    suite: str = Field(default="both", description="quality | security | both")
    engine: str = Field(default="auto", description="auto | offline | ragas")


@router.get("/cases", summary="Golden quality and red-team datasets")
def cases() -> dict[str, object]:
    return {
        "quality": [
            {
                "id": c.case_id,
                "username": c.username,
                "question": c.question,
                "reference": c.reference,
            }
            for c in QUALITY_CASES
        ],
        "security": [
            {
                "id": c.case_id,
                "username": c.username,
                "probe": c.probe,
                "expected": c.expected,
                "question": c.question,
                "notes": c.notes,
            }
            for c in SECURITY_CASES
        ],
    }


@router.post("/run", summary="Run the evaluation suites")
def run(payload: EvalRequest, context: ContextDep, _user: Evaluator) -> dict[str, object]:
    suite = payload.suite.lower()
    engine = payload.engine.lower()
    if suite not in SUITES:
        raise HTTPException(status_code=422, detail=f"suite must be one of {SUITES}")
    if engine not in ENGINES:
        raise HTTPException(status_code=422, detail=f"engine must be one of {ENGINES}")

    report = None
    security = None
    if suite in ("quality", "both"):
        report = run_quality(context, engine=engine)
    if suite in ("security", "both"):
        security = run_red_team(context)

    saved = save_report(report, security, context.settings)
    return {
        "quality": report.as_dict() if report else None,
        "red_team": security.as_dict() if security else None,
        "saved_to": str(saved) if saved else None,
    }


@router.get("/latest", summary="Most recent evaluation report")
def latest(context: ContextDep) -> dict[str, object]:
    path = Path(context.settings.eval_path) / "latest.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No evaluation report has been produced yet.")
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = ["router"]
