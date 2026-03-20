import httpx
from backend.config import settings


LEAK_LOOKUP_BASE = "https://leak-lookup.com/api/search"


async def check_breach(email: str) -> dict:
    """
    Check if an email has appeared in any known data breach using Leak-Lookup API.
    A free API key provides 50 requests per day.
    Falls back to a mock response if no API key is set.
    """
    if not getattr(settings, "LEAKLOOKUP_API_KEY", None):
        return _mock_breach_response(email)

    data = {
        "key": settings.LEAKLOOKUP_API_KEY,
        "type": "email_address",
        "query": email
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(LEAK_LOOKUP_BASE, data=data)
            resp.raise_for_status()
            
            # Leak-Lookup returns json with string "true" or "false" for error
            result = resp.json()
            is_error = str(result.get("error", "false")).lower() == "true"
            msg = result.get("message", "")

            if is_error or not isinstance(msg, dict):
                # Usually means "results not found" or auth error
                if "results not found" in str(msg).lower() or msg == []:
                    return {
                        "identity": email,
                        "found": False,
                        "breach_count": 0,
                        "breaches": [],
                        "message": "Good news — no breaches found for this identity in Leak-Lookup."
                    }
                else:
                    return {"error": f"Leak-Lookup API responded: {msg}"}

            # If found, 'message' is a dict mapping Database Name -> list of leaked entries
            breaches = []
            for db_name, leaks in msg.items():
                if isinstance(leaks, list) and len(leaks) > 0:
                    first_leak = leaks[0]
                    # Attempt to extract available fields
                    keys_leaked = [k for k in first_leak.keys() if first_leak.get(k) and k not in ('id', 'email_address')]
                    
                    breaches.append({
                        "name": db_name,
                        "domain": db_name.lower().replace(" ", "") + ".com",  # LeakLookup doesn't always give domains, so we estimate
                        "data_classes": keys_leaked,
                        "pwn_count": len(leaks), # Entries for this specific person
                    })

            return {
                "identity": email,
                "found": True,
                "breach_count": len(breaches),
                "breaches": breaches,
                "severity": _calculate_severity(breaches),
            }

        except httpx.RequestError as e:
            return {"error": f"Network error contacting Leak-Lookup: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error parsing Leak-Lookup: {str(e)}"}
            
    return {"error": "Failed to complete breach check"}


def _calculate_severity(breaches: list) -> str:
    if not breaches: return "none"
    if len(breaches) > 5:
        return "critical"
    elif len(breaches) > 2:
        return "high"
    elif len(breaches) > 0:
        return "medium"
    return "low"


def _mock_breach_response(email: str) -> dict:
    """
    Demo response when no Leak-Lookup API key is configured.
    Used for UI demonstration purposes at hackathons.
    """
    return {
        "identity": email,
        "found": True,
        "breach_count": 3,
        "severity": "high",
        "note": "DEMO MODE — Set LEAKLOOKUP_API_KEY in .env for real results.",
        "breaches": [
            {
                "name": "Adobe",
                "domain": "adobe.com",
                "breach_date": "2013-10-04",
                "pwn_count": 152445165,
                "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
                "is_sensitive": False,
                "is_verified": True,
            },
            {
                "name": "LinkedIn",
                "domain": "linkedin.com",
                "breach_date": "2016-05-05",
                "pwn_count": 164611595,
                "data_classes": ["Email addresses", "Passwords"],
                "is_sensitive": False,
                "is_verified": True,
            },
            {
                "name": "Citadel_0322",
                "domain": "darkforum.onion",
                "breach_date": "2024-01-15",
                "pwn_count": 8800000,
                "data_classes": ["Email addresses", "Passwords", "Phone numbers", "Physical addresses"],
                "is_sensitive": True,
                "is_verified": False,
            },
        ],
    }
