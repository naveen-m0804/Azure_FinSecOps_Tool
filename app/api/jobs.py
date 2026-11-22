from fastapi import APIRouter, HTTPException
from app.core.session_store import session_store
from app.schemas.job import JobProgressModel, JobResponse, JobStatus

router = APIRouter(prefix="/api/jobs", tags=["Jobs"])

@router.get("/{job_id}", response_model=JobProgressModel)
async def get_job_progress(job_id: str):
    job = await session_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired.")
    return job["progress"]

@router.get("/{job_id}/results", response_model=JobResponse)
async def get_job_results(job_id: str):
    job = await session_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired.")

    return JobResponse(
        job_id=job["job_id"],
        status=job["status"],
        progress=job["progress"],
        summary=job.get("summary", {}),
        results=job.get("results", {})
    )

@router.post("/{job_id}/cancel")
async def cancel_job(job_id: str):
    job = await session_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    await session_store.update_job_progress(job_id=job_id, status=JobStatus.CANCELLED)
    return {"success": True, "message": "Job cancelled."}
