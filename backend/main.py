import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Application & Rules Configuration
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AIDATACY Zero-Knowledge NIS2/ReCyF Scoring Engine",
    description="Processes strictly anonymized compliance metadata to compute NIS2 Readiness Scores.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

RULES_FILE_PATH = Path(__file__).parent / "recyf_rules.json"


def load_rules_Index() -> dict:
    """Loads the modular ReCyF rules JSON configuration from disk, with an embedded fallback."""
    if RULES_FILE_PATH.exists():
        with open(RULES_FILE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {obj["objective_id"]: obj for obj in data.get("objectives", [])}

    # Fallback if main.py is executed outside the directory containing recyf_rules.json
    return {
        10: {
            "objective_id": 10,
            "code": "RECYF-OBJ-10.2",
            "title": "Identity & Access Management (IAM) — Privileged MFA Enforcement",
            "criticality": "CRITICAL",
            "weight": 40,
            "max_score": 100,
            "remediation": {
                "compliant": (
                    "Objective 10 satisfied. Maintain continuous monitoring of privileged "
                    "sessions via AIDATACY Access Gateway."
                ),
                "non_compliant": (
                    "Enforce hardware-backed or FIDO2 MFA for the {failed_count} identified "
                    "non-compliant admin account(s) immediately using AIDATACY Access Gateway "
                    "and revoke active legacy tokens."
                ),
            },
        }
    }


# ---------------------------------------------------------------------------
# Strict Zero-Knowledge Schemas
# ---------------------------------------------------------------------------
class AuditResultSubmission(BaseModel):
    """
    Strictly forbids any extra keys (such as usernames, emails, or raw logs)
    to enforce Zero-Knowledge sovereignty at the API boundary.
    """
    model_config = ConfigDict(extra="forbid")

    objective: int = Field(..., description="ReCyF Objective ID (e.g., 10)")
    rule_code: Optional[str] = Field(default="RECYF-OBJ-10.2", description="Specific ReCyF sub-control code")
    status: Literal["Compliant", "Non-Compliant"] = Field(..., description="Calculated compliance state")
    scoped_assets_count: int = Field(default=1, ge=1, description="Total privileged assets evaluated in scope")
    failed_assets_count: int = Field(..., ge=0, description="Count of privileged assets failing the rule")
    evidence_sha256: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Client-generated SHA-256 fingerprint of the local configuration file",
    )

    @model_validator(mode="after")
    def validate_consistency(self) -> "AuditResultSubmission":
        if self.failed_assets_count > self.scoped_assets_count:
            raise ValueError("failed_assets_count cannot exceed scoped_assets_count.")
        if self.status == "Compliant" and self.failed_assets_count > 0:
            raise ValueError("Status cannot be 'Compliant' when failed_assets_count > 0.")
        if self.status == "Non-Compliant" and self.failed_assets_count == 0:
            raise ValueError("Status 'Non-Compliant' requires failed_assets_count >= 1.")
        return self


class AuditScoreResponse(BaseModel):
    audit_timestamp_utc: str
    objective: int
    rule_code: str
    status: str
    criticality: str
    objective_weight: int
    failed_assets_count: int
    nis2_readiness_score: float
    remediation_recommendation: str
    zero_knowledge_verified: bool


# ---------------------------------------------------------------------------
# Scoring Algorithm & Endpoints
# ---------------------------------------------------------------------------
@app.post(
    "/api/submit-audit-result",
    response_model=AuditScoreResponse,
    status_code=status.HTTP_200_OK,
)
async def submit_audit_result(payload: AuditResultSubmission) -> AuditScoreResponse:
    rules_index = load_rules_Index()
    rule = rules_index.get(payload.objective)

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ReCyF Objective {payload.objective} not found in rules engine configuration.",
        )

    max_score = float(rule.get("max_score", 100))
    weight = int(rule.get("weight", 40))
    criticality = rule.get("criticality", "HIGH")

    # Calculate NIS2 Readiness Score:
    # Base readiness is 100. For CRITICAL objectives like IAM/MFA, any single failure
    # forfeits the full base weight (40 pts) plus a proportional penalty for the failure ratio.
    if payload.status == "Compliant":
        readiness_score = max_score
        remediation_text = rule["remediation"]["compliant"]
    else:
        failure_ratio = payload.failed_assets_count / payload.scoped_assets_count
        criticality_multiplier = 1.5 if criticality == "CRITICAL" else 1.0
        penalty = weight + (weight * failure_ratio * criticality_multiplier)
        readiness_score = max(0.0, round(max_score - penalty, 1))
        remediation_text = rule["remediation"]["non_compliant"].format(
            failed_count=payload.failed_assets_count
        )

    return AuditScoreResponse(
        audit_timestamp_utc=datetime.now(timezone.utc).isoformat(),
        objective=payload.objective,
        rule_code=rule.get("code", payload.rule_code),
        status=payload.status,
        criticality=criticality,
        objective_weight=weight,
        failed_assets_count=payload.failed_assets_count,
        nis2_readiness_score=readiness_score,
        remediation_recommendation=remediation_text,
        zero_knowledge_verified=True,
    )