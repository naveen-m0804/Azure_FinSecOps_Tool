from typing import List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.assessments.registry import assessment_registry
from app.assessments.runner import AssessmentJobRunner
from app.schemas.assessment import AssessmentDefinition

router = APIRouter(prefix="/api/assessments", tags=["Assessments"])

class RunJobRequest(BaseModel):
    connection_id: str

@router.get("", response_model=List[AssessmentDefinition])
async def list_all_assessments():
    return assessment_registry.get_all_definitions()

@router.get("/security", response_model=List[AssessmentDefinition])
async def list_security_assessments():
    return assessment_registry.get_security_definitions()

@router.get("/cost", response_model=List[AssessmentDefinition])
async def list_cost_assessments():
    return assessment_registry.get_cost_definitions()

@router.post("/run-all")
async def run_all_assessments(req: RunJobRequest):
    try:
        job_id = await AssessmentJobRunner.start_job(connection_id=req.connection_id, scope="all")
        return {"job_id": job_id, "status": "Pending", "scope": "all"}
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

@router.post("/run-security")
async def run_security_assessments(req: RunJobRequest):
    try:
        job_id = await AssessmentJobRunner.start_job(connection_id=req.connection_id, scope="security")
        return {"job_id": job_id, "status": "Pending", "scope": "security"}
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

@router.post("/run-cost")
async def run_cost_assessments(req: RunJobRequest):
    try:
        job_id = await AssessmentJobRunner.start_job(connection_id=req.connection_id, scope="cost")
        return {"job_id": job_id, "status": "Pending", "scope": "cost"}
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

@router.post("/{assessment_id}/run")
async def run_single_assessment(assessment_id: str, req: RunJobRequest):
    try:
        job_id = await AssessmentJobRunner.start_job(
            connection_id=req.connection_id,
            single_assessment_id=assessment_id
        )
        return {"job_id": job_id, "status": "Pending", "assessment_id": assessment_id}
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))
