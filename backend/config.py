import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent

class Settings:
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    LEAKLOOKUP_API_KEY: str = os.getenv("LEAKLOOKUP_API_KEY", "")

    NVIDIA_NIM_API_KEY: str = os.getenv("NVIDIA_NIM_API_KEY", "")
    NVIDIA_NIM_MODEL: str = os.getenv("NVIDIA_NIM_MODEL", "meta/llama-3.1-8b-instruct")
    NVIDIA_NIM_BASE_URL: str = "https://integrate.api.nvidia.com/v1/chat/completions"

    APP_NAME: str = "SentinelCore"
    APP_VERSION: str = "4.0"
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./sentinelcore.db")

    ALLOWED_ORIGINS: list = [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "null",
    ]

    DEEPFAKE_MODEL_NAME: str = os.getenv("DEEPFAKE_MODEL", "prithivMLmods/Deep-Fake-Detector-Model")

    RECON_CONTAINER_NAME: str = os.getenv("RECON_CONTAINER_NAME", "sentinelcore-recon-agent")
    RECON_DOCKER_IMAGE: str = os.getenv("RECON_DOCKER_IMAGE", "sentinelcore-recon:latest")
    REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", "./reports")).resolve()

    MAX_CONCURRENT_RECON_JOBS: int = int(os.getenv("MAX_CONCURRENT_RECON_JOBS", "3"))

settings = Settings()
