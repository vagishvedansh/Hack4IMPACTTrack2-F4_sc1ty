"""
Autonomous Recon Router
=======================
API endpoints for AI-orchestrated reconnaissance operations.
"""

import asyncio
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database import get_db, AutonomousReconJob, ReconToolOutput, JobStatus
from backend.services.autonomous_agent import run_recon_job
from backend.config import settings


router = APIRouter(prefix="/api/autonomous", tags=["Autonomous Recon"])


class StartReconRequest(BaseModel):
    target: str


class ReconJobResponse(BaseModel):
    id: int
    target: str
    status: str
    progress: int
    current_step: str | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None


running_jobs: dict[int, asyncio.Task] = {}


async def _run_recon_background(job_id: int, target: str):
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        await run_recon_job(job_id, target, db)
    except Exception as e:
        job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
        if job:
            job.status = JobStatus.FAILED.value
            job.error_message = str(e)
            db.commit()
    finally:
        db.close()
        if job_id in running_jobs:
            del running_jobs[job_id]


@router.post("/start", response_model=dict)
async def start_autonomous_recon(
    request: StartReconRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start an autonomous reconnaissance job on the specified target.
    The AI agent will decide which tools to run and generate a report.
    """
    active_jobs = db.query(AutonomousReconJob).filter(
        AutonomousReconJob.status.in_([JobStatus.PENDING.value, JobStatus.RUNNING.value])
    ).count()

    if active_jobs >= settings.MAX_CONCURRENT_RECON_JOBS:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent recon jobs ({settings.MAX_CONCURRENT_RECON_JOBS}) reached. Please wait."
        )

    job = AutonomousReconJob(target=request.target)
    db.add(job)
    db.commit()
    db.refresh(job)

    task = asyncio.create_task(_run_recon_background(job.id, request.target))
    running_jobs[job.id] = task

    return {
        "job_id": job.id,
        "target": job.target,
        "status": job.status,
        "message": "Autonomous recon job started. Poll /api/autonomous/status/{job_id} for progress."
    }


@router.get("/status/{job_id}", response_model=dict)
async def get_recon_status(job_id: int, db: Session = Depends(get_db)):
    """
    Get the current status of a reconnaissance job.
    """
    job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")

    return {
        "id": job.id,
        "target": job.target,
        "status": job.status,
        "progress": job.progress,
        "current_step": job.current_step,
        "tools_used": json.loads(job.tools_used) if job.tools_used else [],
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.get("/report/{job_id}")
async def get_recon_report(job_id: int, db: Session = Depends(get_db)):
    """
    Get the full reconnaissance report for a completed job.
    Returns markdown content that can be rendered in the frontend.
    """
    job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")

    if job.status not in [JobStatus.COMPLETED.value, JobStatus.FAILED.value]:
        raise HTTPException(
            status_code=400,
            detail=f"Job is still {job.status}. Please wait for completion."
        )

    return {
        "id": job.id,
        "target": job.target,
        "status": job.status,
        "report": job.report_markdown,
        "tools_used": json.loads(job.tools_used) if job.tools_used else [],
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.get("/report/{job_id}/download")
async def download_recon_report(job_id: int, db: Session = Depends(get_db)):
    """
    Download the reconnaissance report as a markdown file.
    """
    job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")

    if job.status != JobStatus.COMPLETED.value:
        raise HTTPException(status_code=400, detail="Job not completed yet")

    filename = f"recon_report_{job.target}_{job.id}.md"
    return PlainTextResponse(
        content=job.report_markdown or "No report generated",
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/history", response_model=list)
async def get_recon_history(limit: int = 20, db: Session = Depends(get_db)):
    """
    Get a list of recent reconnaissance jobs.
    """
    jobs = db.query(AutonomousReconJob).order_by(
        AutonomousReconJob.created_at.desc()
    ).limit(limit).all()

    return [
        {
            "id": job.id,
            "target": job.target,
            "status": job.status,
            "progress": job.progress,
            "tools_used": json.loads(job.tools_used) if job.tools_used else [],
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        }
        for job in jobs
    ]


@router.get("/outputs/{job_id}")
async def get_tool_outputs(job_id: int, db: Session = Depends(get_db)):
    """
    Get all raw tool outputs for a specific recon job.
    Useful for debugging or detailed analysis.
    """
    job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")

    outputs = db.query(ReconToolOutput).filter(
        ReconToolOutput.job_id == job_id
    ).order_by(ReconToolOutput.created_at.asc()).all()

    return {
        "job_id": job_id,
        "target": job.target,
        "outputs": [
            {
                "id": out.id,
                "tool_name": out.tool_name,
                "command": out.command,
                "raw_output": out.raw_output,
                "execution_time_seconds": out.execution_time_seconds,
                "created_at": out.created_at.isoformat() if out.created_at else None,
            }
            for out in outputs
        ]
    }


@router.post("/cancel/{job_id}")
async def cancel_recon_job(job_id: int, db: Session = Depends(get_db)):
    """
    Cancel a running reconnaissance job.
    """
    job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")

    if job.status not in [JobStatus.PENDING.value, JobStatus.RUNNING.value]:
        raise HTTPException(status_code=400, detail="Job cannot be cancelled (already completed or failed)")

    if job_id in running_jobs:
        running_jobs[job_id].cancel()
        del running_jobs[job_id]

    job.status = JobStatus.CANCELLED.value
    db.commit()

    return {"message": "Job cancelled", "job_id": job_id}


@router.delete("/{job_id}")
async def delete_recon_job(job_id: int, db: Session = Depends(get_db)):
    """
    Delete a reconnaissance job and its associated data.
    """
    job = db.query(AutonomousReconJob).filter(AutonomousReconJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")

    db.query(ReconToolOutput).filter(ReconToolOutput.job_id == job_id).delete()
    db.delete(job)
    db.commit()

    if job.report_path:
        report_file = Path(job.report_path)
        if report_file.exists():
            report_file.unlink()

    return {"message": "Job deleted", "job_id": job_id}
