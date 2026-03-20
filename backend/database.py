from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import enum
from backend.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_type = Column(String)
    verdict = Column(String)
    threat_name = Column(String, nullable=True)
    heuristic_score = Column(Integer, nullable=True)
    raw_response = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ReconResult(Base):
    __tablename__ = "recon_results"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True)
    whois_data = Column(Text, nullable=True)
    open_ports = Column(Text, nullable=True)
    subdomains = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class BreachResult(Base):
    __tablename__ = "breach_results"

    id = Column(Integer, primary_key=True, index=True)
    identity = Column(String, index=True)
    breaches = Column(Text, nullable=True)
    found = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class DeepfakeResult(Base):
    __tablename__ = "deepfake_results"

    id = Column(Integer, primary_key=True, index=True)
    media_url = Column(String)
    confidence_pct = Column(Float)
    verdict = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class AutonomousReconJob(Base):
    __tablename__ = "autonomous_recon_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    status = Column(String, default=JobStatus.PENDING.value)
    progress = Column(Integer, default=0)
    current_step = Column(String, nullable=True)
    report_markdown = Column(Text, nullable=True)
    report_path = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    tools_used = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ReconToolOutput(Base):
    __tablename__ = "recon_tool_outputs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, index=True)
    tool_name = Column(String)
    command = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)
    parsed_findings = Column(Text, nullable=True)
    execution_time_seconds = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
