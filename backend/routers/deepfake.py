import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.services import deepfake_ml
from backend.database import get_db, DeepfakeResult

router = APIRouter(prefix="/api/deepfake", tags=["Deepfake Detection"])


class DeepfakeRequest(BaseModel):
    url: str


@router.post("/analyze")
async def analyze_media(request: DeepfakeRequest, db: Session = Depends(get_db)):
    """
    Download an image from the URL and run deepfake detection.
    Returns confidence percentage and REAL/FAKE verdict.
    """
    result = await deepfake_ml.analyze_media(request.url.strip())

    if "error" not in result:
        db.add(DeepfakeResult(
            media_url=request.url.strip(),
            confidence_pct=result.get("confidence_pct", 0),
            verdict=result.get("verdict", "UNKNOWN"),
        ))
        db.commit()

    return result


@router.get("/history")
async def deepfake_history(limit: int = 20, db: Session = Depends(get_db)):
    """Retrieve recent deepfake analysis results."""
    records = db.query(DeepfakeResult).order_by(DeepfakeResult.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "media_url": r.media_url,
            "confidence_pct": r.confidence_pct,
            "verdict": r.verdict,
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]
