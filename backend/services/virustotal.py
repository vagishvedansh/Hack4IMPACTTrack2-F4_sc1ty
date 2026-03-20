import httpx
import asyncio
import base64
from backend.config import settings


VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": settings.VIRUSTOTAL_API_KEY}


async def scan_url(url: str) -> dict:
    """Submit a URL to VirusTotal and return the full analysis report."""
    if not settings.VIRUSTOTAL_API_KEY:
        return _mock_scan_result(url, "url")

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            # Step 1: Submit URL for analysis
            encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            submit_resp = await client.post(
                f"{VIRUSTOTAL_BASE}/urls",
                headers=HEADERS,
                data={"url": url}
            )
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()["data"]["id"]

            # Step 2: Poll for results (up to 30s)
            for _ in range(10):
                await asyncio.sleep(3)
                result_resp = await client.get(
                    f"{VIRUSTOTAL_BASE}/analyses/{analysis_id}",
                    headers=HEADERS
                )
                result_resp.raise_for_status()
                data = result_resp.json()
                status = data["data"]["attributes"]["status"]
                if status == "completed":
                    return _parse_vt_result(data, url, "url")

            return {"error": "Analysis timed out", "target": url}
        except Exception as e:
            return {"error": f"VirusTotal API error: {str(e)}", "target": url}


async def scan_file_hash(file_hash: str) -> dict:
    """Lookup a file hash (MD5/SHA1/SHA256) on VirusTotal."""
    if not settings.VIRUSTOTAL_API_KEY:
        return _mock_scan_result(file_hash, "file")

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{VIRUSTOTAL_BASE}/files/{file_hash}",
            headers=HEADERS
        )
        if resp.status_code == 404:
            return {"verdict": "unknown", "target": file_hash, "message": "Hash not found in VirusTotal database."}
        resp.raise_for_status()
        return _parse_vt_result(resp.json(), file_hash, "file")


async def scan_file_bytes(file_bytes: bytes, filename: str) -> dict:
    """Upload a file directly to VirusTotal for analysis."""
    if not settings.VIRUSTOTAL_API_KEY:
        return _mock_scan_result(filename, "file")

    async with httpx.AsyncClient(timeout=60) as client:
        upload_resp = await client.post(
            f"{VIRUSTOTAL_BASE}/files",
            headers=HEADERS,
            files={"file": (filename, file_bytes)}
        )
        upload_resp.raise_for_status()
        analysis_id = upload_resp.json()["data"]["id"]

        for _ in range(15):
            await asyncio.sleep(4)
            result_resp = await client.get(
                f"{VIRUSTOTAL_BASE}/analyses/{analysis_id}",
                headers=HEADERS
            )
            result_resp.raise_for_status()
            data = result_resp.json()
            if data["data"]["attributes"]["status"] == "completed":
                return _parse_vt_result(data, filename, "file")

        return {"error": "File analysis timed out", "target": filename}


def _parse_vt_result(data: dict, target: str, scan_type: str) -> dict:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {})

    malicious_count  = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    total_engines    = sum(stats.values()) if stats else 0
    heuristic_score  = int((malicious_count / total_engines) * 100) if total_engines else 0

    if malicious_count > 5:
        verdict = "malicious"
        threat_name = _extract_threat_name(attrs)
    elif malicious_count > 0 or suspicious_count > 3:
        verdict = "suspicious"
        threat_name = _extract_threat_name(attrs)
    else:
        verdict = "clean"
        threat_name = None

    return {
        "target": target,
        "scan_type": scan_type,
        "verdict": verdict,
        "threat_name": threat_name,
        "heuristic_score": heuristic_score,
        "malicious_engines": malicious_count,
        "suspicious_engines": suspicious_count,
        "total_engines": total_engines,
        "stats": stats,
    }


def _extract_threat_name(attrs: dict) -> str:
    results = attrs.get("results", {})
    for engine, data in results.items():
        name = data.get("result")
        if name:
            return name
    return "Unknown Threat"


def _mock_scan_result(target: str, scan_type: str) -> dict:
    """
    Demo response when no VirusTotal API key is configured.
    Returns a randomised but realistic-looking threat report.
    """
    import random
    malicious = random.randint(8, 42)
    total = 72
    score = int((malicious / total) * 100)
    threats = [
        "Trojan.PHP.GenericKD", "Win32.Backdoor.CobaltStrike",
        "JS.Miner.CryptoNight", "HEUR:Trojan.Script.Miner.gen",
        "Exploit.CVE-2024-3899", "Ransom.WannaCry.B",
    ]
    return {
        "target": target,
        "scan_type": scan_type,
        "verdict": "malicious" if malicious > 5 else "clean",
        "threat_name": random.choice(threats),
        "heuristic_score": score,
        "malicious_engines": malicious,
        "suspicious_engines": random.randint(0, 5),
        "total_engines": total,
        "stats": {"malicious": malicious, "suspicious": random.randint(0, 5), "harmless": total - malicious, "undetected": 0},
        "note": "DEMO MODE — Set VIRUSTOTAL_API_KEY in .env for real results.",
    }
