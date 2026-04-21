from datetime import datetime

from sqlalchemy import Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    device_serial: Mapped[str]
    command_type: Mapped[str]   # manifest_analysis | permission_audit | exported_components |
                                 # content_provider | intent_exploit | ipc_analysis | shell
    args: Mapped[str | None] = mapped_column(Text)      # JSON
    result: Mapped[str | None] = mapped_column(Text)    # JSON
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | error
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None]


class OllamaAnalysis(Base):
    __tablename__ = "ollama_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())

    session_id: Mapped[int | None] = mapped_column(default=None)
    source: Mapped[str]  # static | owasp | cve | fuzzing | tls | jwt | frida | strix | manual
    scan_input: Mapped[str] = mapped_column(Text)
    ai_response: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | error
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None]
    model_used: Mapped[str] = mapped_column(default="metatron-qwen")


class StrixScan(Base):
    __tablename__ = "strix_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())

    # Link to a BluJay session (optional — can run standalone)
    session_id: Mapped[int | None] = mapped_column(default=None)

    # Strix target — URL, IP, or local path extracted from mobile app analysis
    target: Mapped[str]

    # Scan configuration
    scan_mode: Mapped[str] = mapped_column(default="standard")  # quick | standard | deep
    instruction: Mapped[str | None] = mapped_column(Text)
    llm_model: Mapped[str] = mapped_column(default="ollama/metatron-qwen")

    # Runtime state
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | error | cancelled
    pid: Mapped[int | None] = mapped_column(default=None)
    run_name: Mapped[str | None] = mapped_column(default=None)  # strix_runs/<run_name>

    # Results
    raw_output: Mapped[str | None] = mapped_column(Text)
    findings_json: Mapped[str | None] = mapped_column(Text)
    vuln_count: Mapped[int | None] = mapped_column(default=0)
    risk_level: Mapped[str | None] = mapped_column(default=None)  # CRITICAL | HIGH | MEDIUM | LOW | NONE

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    duration_seconds: Mapped[float | None] = mapped_column(default=None)

    error: Mapped[str | None] = mapped_column(Text)
