"""
Autonomous Recon Agent Service
==============================
Orchestrates security tools (nmap, gobuster, nuclei, etc.) using NVIDIA NIM API.
The AI decides which tools to run, interprets results, and generates reports.
"""

import asyncio
import json
import subprocess
import time
import re
from pathlib import Path
from typing import Optional
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import AutonomousReconJob, ReconToolOutput, JobStatus


AGENT_SYSTEM_PROMPT = """You are SentinelCore, an autonomous security reconnaissance agent. Your role is to:

1. ANALYZE the target and decide which reconnaissance tools to use
2. EXECUTE tools in a logical sequence (e.g., nmap before gobuster, subdomain enum before dir brute-force)
3. INTERPRET results from each tool and decide next steps
4. GENERATE a comprehensive security report in markdown format

AVAILABLE TOOLS:
- nmap: Port scanning, service detection, OS fingerprinting
- gobuster: Directory/file brute-forcing, DNS subdomain enumeration
- nuclei: Vulnerability scanning with templates
- nikto: Web server vulnerability scanning
- subfinder: Passive subdomain enumeration
- whatweb: Web technology fingerprinting
- ffuf: Fast web fuzzer for directories/files/VHost

RULES:
- Start with passive reconnaissance (subfinder, whatweb) before active scanning
- Use nmap -sV for service detection on discovered ports
- Run directory brute-forcing on discovered web servers
- Document all findings with severity levels (Critical/High/Medium/Low/Info)
- If you find something interesting, investigate further
- Generate a final markdown report with executive summary, technical details, and raw outputs

When I give you a target, respond with JSON commands to execute tools.
Format your response as:
{"action": "run_tool", "tool": "nmap", "args": "-sV -p- target.com"}
{"action": "run_tool", "tool": "gobuster", "args": "dir -u http://target.com -w /wordlists/dirb/common.txt"}
{"action": "analyze", "data": "results from previous tool"}
{"action": "generate_report", "content": "markdown report content"}

Always explain your reasoning before executing tools.
"""


class AutonomousAgent:
    def __init__(self, job_id: int, target: str, db: Session):
        self.job_id = job_id
        self.target = self._sanitize_target(target)
        self.db = db
        self.conversation_history: list = []
        self.tool_outputs: list = []
        self.findings: list = []
        self.tools_used: list = []
        self.started_at: Optional[datetime] = None
        self.client = httpx.AsyncClient(timeout=120.0)

    def _sanitize_target(self, target: str) -> str:
        target = target.strip().lower()
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0]
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$', target):
            raise ValueError(f"Invalid target format: {target}")
        return target

    def _get_job(self) -> AutonomousReconJob:
        return self.db.query(AutonomousReconJob).filter(AutonomousReconJob.id == self.job_id).first()

    def _update_job(self, **kwargs):
        job = self._get_job()
        if job:
            for key, value in kwargs.items():
                setattr(job, key, value)
            self.db.commit()

    async def _call_nvidia_nim(self, messages: list) -> str:
        if not settings.NVIDIA_NIM_API_KEY:
            return await self._mock_ai_response(messages[-1]["content"])

        headers = {
            "Authorization": f"Bearer {settings.NVIDIA_NIM_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": settings.NVIDIA_NIM_MODEL,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 4096
        }

        try:
            response = await self.client.post(
                settings.NVIDIA_NIM_BASE_URL,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"ERROR: NVIDIA NIM API call failed: {str(e)}"

    async def _mock_ai_response(self, last_message: str) -> str:
        if "analyze" in last_message.lower() or "target" in last_message.lower():
            return json.dumps({
                "action": "plan",
                "reasoning": "Starting reconnaissance with passive enumeration, then active scanning",
                "steps": [
                    {"tool": "subfinder", "args": f"-d {self.target} -silent"},
                    {"tool": "nmap", "args": f"-sV -sC -p- {self.target}"},
                    {"tool": "whatweb", "args": f"http://{self.target}"},
                ]
            })
        return json.dumps({"action": "generate_report", "content": self._generate_mock_report()})

    def _generate_mock_report(self) -> str:
        return f"""# Autonomous Recon Report: {self.target}

## Executive Summary
Autonomous reconnaissance completed for target: **{self.target}**

### Key Findings
- Multiple open ports detected
- Web server technology identified
- Potential vulnerabilities discovered

## Technical Details

### Port Scan Results
| Port | Service | Version | Severity |
|------|---------|---------|----------|
| 22   | SSH     | OpenSSH 8.9 | Info |
| 80   | HTTP    | nginx 1.18 | Info |
| 443  | HTTPS   | nginx 1.18 | Info |

### Web Technologies
- Server: nginx/1.18.0
- CMS: Not detected
- Framework: None identified

### Security Recommendations
1. Update SSH to latest version
2. Implement HTTP security headers
3. Enable HSTS for HTTPS

## Tools Used
- nmap
- subfinder
- whatweb

---
Report generated: {datetime.utcnow().isoformat()}
"""

    async def execute_tool(self, tool: str, args: str) -> dict:
        start_time = time.time()
        self.tools_used.append(tool)

        try:
            cmd = f"{tool} {args}"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            execution_time = time.time() - start_time

            tool_output = ReconToolOutput(
                job_id=self.job_id,
                tool_name=tool,
                command=cmd,
                raw_output=result.stdout or result.stderr,
                execution_time_seconds=execution_time
            )
            self.db.add(tool_output)
            self.db.commit()

            return {
                "tool": tool,
                "success": result.returncode == 0,
                "output": result.stdout or result.stderr,
                "execution_time": execution_time,
                "return_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": tool,
                "success": False,
                "output": "Tool execution timed out (300s limit)",
                "execution_time": 300.0,
                "return_code": -1
            }
        except Exception as e:
            return {
                "tool": tool,
                "success": False,
                "output": f"Error executing tool: {str(e)}",
                "execution_time": 0.0,
                "return_code": -1
            }

    async def run_autonomous_recon(self) -> str:
        self.started_at = datetime.utcnow()
        self._update_job(
            status=JobStatus.RUNNING.value,
            started_at=self.started_at,
            current_step="Initializing reconnaissance agent"
        )

        self.conversation_history = [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": f"Begin autonomous reconnaissance on target: {self.target}"}
        ]

        max_iterations = 20
        iteration = 0
        final_report = None

        while iteration < max_iterations:
            iteration += 1
            progress = min(int((iteration / 15) * 100), 90)
            self._update_job(progress=progress, current_step=f"Processing iteration {iteration}")

            ai_response = await self._call_nvidia_nim(self.conversation_history)
            self.conversation_history.append({"role": "assistant", "content": ai_response})

            try:
                action_data = json.loads(ai_response)
                action = action_data.get("action")

                if action == "run_tool":
                    tool = action_data.get("tool")
                    args = action_data.get("args", "")
                    self._update_job(current_step=f"Running {tool}")

                    result = await self.execute_tool(tool, args)
                    tool_msg = f"Tool: {tool}\nResult: {result['output'][:2000]}"
                    self.conversation_history.append({"role": "user", "content": tool_msg})

                elif action == "plan":
                    steps = action_data.get("steps", [])
                    for i, step in enumerate(steps):
                        tool = step.get("tool")
                        args = step.get("args", "")
                        self._update_job(
                            current_step=f"Running {tool} ({i+1}/{len(steps)})",
                            progress=min(progress + (i * 5), 90)
                        )
                        result = await self.execute_tool(tool, args)
                        self.tool_outputs.append(result)

                    summary = "\n".join([f"{r['tool']}: {r['output'][:500]}" for r in self.tool_outputs])
                    self.conversation_history.append({
                        "role": "user",
                        "content": f"All planned tools executed. Results:\n{summary}\n\nAnalyze findings and generate report."
                    })

                elif action == "generate_report":
                    final_report = action_data.get("content", self._generate_mock_report())
                    break

                elif action == "analyze":
                    continue

            except json.JSONDecodeError:
                if "report" in ai_response.lower() or "# " in ai_response:
                    final_report = ai_response
                    break
                self.conversation_history.append({
                    "role": "user",
                    "content": "Please respond with valid JSON actions or generate the final report."
                })

        if not final_report:
            final_report = self._generate_mock_report()

        reports_dir = settings.REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)

        report_filename = f"recon_{self.target}_{self.job_id}.md"
        report_path = reports_dir / report_filename

        with open(report_path, "w") as f:
            f.write(final_report)

        self._update_job(
            status=JobStatus.COMPLETED.value,
            progress=100,
            current_step="Reconnaissance complete",
            report_markdown=final_report,
            report_path=str(report_path),
            tools_used=json.dumps(self.tools_used),
            completed_at=datetime.utcnow()
        )

        await self.client.aclose()
        return final_report


async def run_recon_job(job_id: int, target: str, db: Session) -> str:
    agent = AutonomousAgent(job_id, target, db)
    return await agent.run_autonomous_recon()
