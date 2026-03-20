# SentinelCore Autonomous Recon Agent Container
# ==============================================
# Contains all security tools + Python runtime for the AI agent

FROM kalilinux/kali-rolling:latest

LABEL maintainer="SentinelCore"
LABEL description="Autonomous reconnaissance agent with security tools"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    gobuster \
    nikto \
    ffuf \
    subfinder \
    whatweb \
    curl \
    wget \
    git \
    seclists \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    httpx \
    pydantic \
    python-dotenv \
    aiohttp

RUN mkdir -p /opt/recon/wordlists && \
    cp /usr/share/seclists/Discovery/Web-Content/common.txt /opt/recon/wordlists/ && \
    cp /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt /opt/recon/wordlists/ && \
    cp /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt /opt/recon/wordlists/

RUN mkdir -p /opt/recon/reports /opt/recon/workspace

WORKDIR /opt/recon

RUN curl -L https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip && \
    chmod +x nuclei && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip && \
    nuclei -update-templates

COPY agent_entrypoint.sh /opt/recon/agent_entrypoint.sh
RUN chmod +x /opt/recon/agent_entrypoint.sh

ENV REPORTS_DIR=/opt/recon/reports
ENV WORDLISTS_DIR=/opt/recon/wordlists

ENTRYPOINT ["/opt/recon/agent_entrypoint.sh"]
