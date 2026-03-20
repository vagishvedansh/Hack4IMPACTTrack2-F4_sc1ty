import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.services import hibp
from backend.database import get_db, BreachResult

router = APIRouter(prefix="/api/darkweb", tags=["Dark Web Watch"])


class BreachCheckRequest(BaseModel):
    identity: str


@router.post("/check")
async def check_identity(request: BreachCheckRequest, db: Session = Depends(get_db)):
    """
    Check an email / alias against HaveIBeenPwned breach database.
    Falls back to demo data if no HIBP API key is configured.
    """
    result = await hibp.check_breach(request.identity.strip())

    if "error" not in result:
        db.add(BreachResult(
            identity=request.identity.strip(),
            breaches=json.dumps(result.get("breaches", [])),
            found=result.get("breach_count", 0),
        ))
        db.commit()

    return result


@router.get("/history")
async def breach_history(limit: int = 20, db: Session = Depends(get_db)):
    """Retrieve recent breach check results from the local database."""
    records = db.query(BreachResult).order_by(BreachResult.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "identity": r.identity,
            "found": r.found,
            "breaches": json.loads(r.breaches or "[]"),
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]
