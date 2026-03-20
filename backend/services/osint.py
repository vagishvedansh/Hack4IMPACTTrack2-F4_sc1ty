import asyncio
import json
import socket
import whois
import httpx
from typing import AsyncGenerator


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]


async def full_recon(domain: str) -> AsyncGenerator[dict, None]:
    """
    Async generator that yields log events for real-time streaming.
    Runs WHOIS, port scan, and subdomain enum in sequence.
    """
    yield {"type": "info", "msg": f"Starting recon on: {domain}"}

    # --- WHOIS ---
    yield {"type": "info", "msg": "Running WHOIS lookup..."}
    whois_data = await _run_whois(domain)
    if "error" in whois_data:
        yield {"type": "warn", "msg": f"WHOIS failed: {whois_data['error']}"}
    else:
        yield {"type": "success", "msg": f"WHOIS: Registrar = {whois_data.get('registrar', 'N/A')}"}
        yield {"type": "info",    "msg": f"WHOIS: Org      = {whois_data.get('org', 'N/A')}"}
        yield {"type": "info",    "msg": f"WHOIS: Country  = {whois_data.get('country', 'N/A')}"}

    # --- DNS Resolution ---
    yield {"type": "info", "msg": "Resolving DNS records..."}
    ip = await _resolve_dns(domain)
    if ip:
        yield {"type": "success", "msg": f"DNS A Record → {ip}"}
    else:
        yield {"type": "warn", "msg": "Could not resolve DNS for domain."}

    # --- Port Scan ---
    yield {"type": "info", "msg": f"Scanning {len(COMMON_PORTS)} common ports..."}
    open_ports = []
    for port in COMMON_PORTS:
        is_open = await _check_port(ip or domain, port)
        if is_open:
            svc = _port_service(port)
            open_ports.append({"port": port, "service": svc})
            yield {"type": "warn", "msg": f"OPEN PORT {port}/tcp — {svc}"}
        await asyncio.sleep(0.05)  # small delay to avoid hammering

    if not open_ports:
        yield {"type": "success", "msg": "No common ports found open (or host filtered)."}

    # --- Subdomain Brute Force (lightweight) ---
    yield {"type": "info", "msg": "Brute-forcing common subdomains..."}
    subs = await _subdomain_enum(domain)
    for sub in subs:
        yield {"type": "warn", "msg": f"Subdomain found: {sub}"}
    if not subs:
        yield {"type": "success", "msg": "No additional subdomains discovered."}

    # --- Final Summary ---
    yield {
        "type": "result",
        "msg": "Recon complete.",
        "data": {
            "domain": domain,
            "ip": ip,
            "whois": whois_data,
            "open_ports": open_ports,
            "subdomains": subs,
        }
    }


async def _run_whois(domain: str) -> dict:
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        return {
            "registrar": w.registrar,
            "org": w.org,
            "country": w.country,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}


async def _resolve_dns(domain: str) -> str | None:
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return result
    except Exception:
        return None


async def _check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _subdomain_enum(domain: str) -> list[str]:
    wordlist = ["www", "mail", "ftp", "admin", "dev", "api", "git", "vpn", "staging", "test", "beta", "portal", "cdn", "ns1", "ns2"]
    found = []
    tasks = [_resolve_dns(f"{sub}.{domain}") for sub in wordlist]
    results = await asyncio.gather(*tasks)
    for sub, ip in zip(wordlist, results):
        if ip:
            found.append(f"{sub}.{domain} → {ip}")
    return found


def _port_service(port: int) -> str:
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev",
        9200: "Elasticsearch", 27017: "MongoDB"
    }
    return services.get(port, "Unknown")
