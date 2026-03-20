import json
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.services import virustotal
from backend.database import get_db, ScanResult

router = APIRouter(prefix="/api/scan", tags=["Malware & File Scan"])


class URLScanRequest(BaseModel):
    url: str

class HashScanRequest(BaseModel):
    hash: str


@router.post("/url")
async def scan_url(request: URLScanRequest, db: Session = Depends(get_db)):
    """Scan a URL against VirusTotal's threat intelligence network."""
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    result = await virustotal.scan_url(request.url)

    if "error" not in result:
        db.add(ScanResult(
            target=result["target"],
            scan_type="url",
            verdict=result["verdict"],
            threat_name=result.get("threat_name"),
            heuristic_score=result.get("heuristic_score"),
            raw_response=json.dumps(result),
        ))
        db.commit()

    return result


@router.post("/hash")
async def scan_hash(request: HashScanRequest, db: Session = Depends(get_db)):
    """Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal."""
    result = await virustotal.scan_file_hash(request.hash)

    if "error" not in result:
        db.add(ScanResult(
            target=result["target"],
            scan_type="file",
            verdict=result.get("verdict", "unknown"),
            threat_name=result.get("threat_name"),
            heuristic_score=result.get("heuristic_score"),
            raw_response=json.dumps(result),
        ))
        db.commit()

    return result


@router.post("/file")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload a file directly for VirusTotal analysis (max 32MB free tier)."""
    MAX_SIZE = 32 * 1024 * 1024  # 32 MB
    contents = await file.read()

    if len(contents) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 32MB VirusTotal free-tier limit.")

    result = await virustotal.scan_file_bytes(contents, file.filename or "upload")

    if "error" not in result:
        db.add(ScanResult(
            target=file.filename or "upload",
            scan_type="file",
            verdict=result.get("verdict", "unknown"),
            threat_name=result.get("threat_name"),
            heuristic_score=result.get("heuristic_score"),
            raw_response=json.dumps(result),
        ))
        db.commit()

    return result


@router.get("/history")
async def scan_history(limit: int = 20, db: Session = Depends(get_db)):
    """Retrieve recent scan results from the local database."""
    records = db.query(ScanResult).order_by(ScanResult.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "target": r.target,
            "scan_type": r.scan_type,
            "verdict": r.verdict,
            "threat_name": r.threat_name,
            "heuristic_score": r.heuristic_score,
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]
