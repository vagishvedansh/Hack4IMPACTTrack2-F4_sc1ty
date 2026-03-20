#!/bin/bash
# SentinelCore Recon Agent Entrypoint
# =====================================
# This script initializes the recon agent and executes commands from the backend

set -e

echo "[+] SentinelCore Recon Agent Started"
echo "[+] Available tools: nmap, gobuster, nuclei, nikto, ffuf, subfinder, whatweb"
echo "[+] Wordlists: /opt/recon/wordlists/"
echo "[+] Reports directory: /opt/recon/reports/"

if [ "$1" = "shell" ]; then
    exec /bin/bash
fi

if [ "$1" = "run" ]; then
    shift
    echo "[+] Executing: $@"
    exec "$@"
fi

if [ "$1" = "nmap" ]; then
    shift
    exec nmap "$@"
fi

if [ "$1" = "gobuster" ]; then
    shift
    exec gobuster "$@"
fi

if [ "$1" = "nuclei" ]; then
    shift
    exec nuclei "$@"
fi

if [ "$1" = "nikto" ]; then
    shift
    exec nikto "$@"
fi

if [ "$1" = "ffuf" ]; then
    shift
    exec ffuf "$@"
fi

if [ "$1" = "subfinder" ]; then
    shift
    exec subfinder "$@"
fi

if [ "$1" = "whatweb" ]; then
    shift
    exec whatweb "$@"
fi

echo "[!] Unknown command. Available: nmap, gobuster, nuclei, nikto, ffuf, subfinder, whatweb, run, shell"
exec /bin/bash
