"""
SentinelCore — FastAPI Backend Entry Point
==========================================
Run with:  python -m backend.main
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import create_tables, get_db, ScanResult, ReconResult, BreachResult, DeepfakeResult, AutonomousReconJob
from backend.routers import scan, recon, darkweb, deepfake, autonomous

# Project root (where index.html lives)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    print(f"[+] {settings.APP_NAME} v{settings.APP_VERSION} — tables ready")
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Autonomous Cyber Defense Backend",
    lifespan=lifespan,
)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Serve frontend ---
@app.get("/", include_in_schema=False)
async def serve_frontend():
    """Serve index.html from the project root."""
    index_path = PROJECT_ROOT / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), media_type="text/html")
    return {"error": "index.html not found"}


# --- Health check ---
@app.get("/api/health")
async def health():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
    }


# --- Live Dashboard Stats ---
@app.get("/api/stats")
async def dashboard_stats(db: Session = Depends(get_db)):
    """Return real-time aggregate stats from the database for the dashboard."""
    total_scans = db.query(ScanResult).count()
    malicious_scans = db.query(ScanResult).filter(ScanResult.verdict == "malicious").count()
    total_recons = db.query(ReconResult).count()
    total_breaches = db.query(BreachResult).count()
    breach_identities_found = db.query(BreachResult).filter(BreachResult.found > 0).count()
    total_deepfakes = db.query(DeepfakeResult).count()
    fakes_detected = db.query(DeepfakeResult).filter(DeepfakeResult.verdict == "FAKE").count()
    total_autonomous = db.query(AutonomousReconJob).count()
    completed_autonomous = db.query(AutonomousReconJob).filter(
        AutonomousReconJob.status == "completed"
    ).count()

    return {
        "total_scans": total_scans,
        "malicious_scans": malicious_scans,
        "total_recons": total_recons,
        "total_breaches": total_breaches,
        "breach_identities_found": breach_identities_found,
        "total_deepfakes": total_deepfakes,
        "fakes_detected": fakes_detected,
        "files_scanned": total_scans + total_deepfakes,
        "threats_found": malicious_scans + breach_identities_found + fakes_detected,
        "autonomous_jobs": total_autonomous,
        "autonomous_completed": completed_autonomous,
    }


# --- Register Routers ---
app.include_router(scan.router)
app.include_router(recon.router)
app.include_router(darkweb.router)
app.include_router(deepfake.router)
app.include_router(autonomous.router)


# --- Direct run ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8080, reload=True)

