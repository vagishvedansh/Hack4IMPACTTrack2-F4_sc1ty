import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.services import osint
from backend.database import get_db, ReconResult

router = APIRouter(prefix="/api/recon", tags=["Recon & OSINT"])


class ReconRequest(BaseModel):
    domain: str


@router.post("/")
async def run_recon(request: ReconRequest, db: Session = Depends(get_db)):
    """
    Run a full synchronous recon job and return all results at once.
    For real-time streaming, use the WebSocket endpoint below.
    """
    domain = request.domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    all_events = []
    result_data = {}

    async for event in osint.full_recon(domain):
        all_events.append(event)
        if event["type"] == "result":
            result_data = event.get("data", {})

    # Persist to DB
    db.add(ReconResult(
        domain=domain,
        whois_data=json.dumps(result_data.get("whois", {})),
        open_ports=json.dumps(result_data.get("open_ports", [])),
        subdomains=json.dumps(result_data.get("subdomains", [])),
    ))
    db.commit()

    return {"domain": domain, "events": all_events, "result": result_data}


@router.websocket("/ws")
async def recon_stream(websocket: WebSocket):
    """
    WebSocket endpoint for real-time recon streaming.
    Client sends: {"domain": "example.com"}
    Server streams: {"type": "info"|"warn"|"success"|"result", "msg": "..."}
    """
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        domain = data.get("domain", "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

        if not domain:
            await websocket.send_json({"type": "error", "msg": "No domain provided."})
            await websocket.close()
            return

        async for event in osint.full_recon(domain):
            await websocket.send_json(event)
            await asyncio.sleep(0)  # yield to event loop

        await websocket.close()

    except WebSocketDisconnect:
        pass


@router.get("/history")
async def recon_history(limit: int = 20, db: Session = Depends(get_db)):
    records = db.query(ReconResult).order_by(ReconResult.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "open_ports": json.loads(r.open_ports or "[]"),
            "subdomains": json.loads(r.subdomains or "[]"),
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]
