import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Timestamped:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class Role(Base, Timestamped):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")


class User(Base, Timestamped):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(40), default="viewer", nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ProviderConfiguration(Base, Timestamped):
    __tablename__ = "provider_configurations"
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # References a server-side environment variable; raw API keys are never persisted.
    secret_env_var: Mapped[str | None] = mapped_column(String(100), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(40), default="not_tested")


class TestTarget(Base, Timestamped):
    __tablename__ = "test_targets"
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False, default="demo_chatbot")
    base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    owner: Mapped[str] = mapped_column(String(120), default="local-admin")
    status: Mapped[str] = mapped_column(String(40), default="approved")


class TestSuite(Base, Timestamped):
    __tablename__ = "test_suites"
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    categories: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class TestCase(Base, Timestamped):
    __tablename__ = "test_cases"
    suite_id: Mapped[str] = mapped_column(ForeignKey("test_suites.id"), nullable=False)
    test_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    criteria: Mapped[dict] = mapped_column(JSON, default=dict)


class TestRun(Base, Timestamped):
    __tablename__ = "test_runs"
    target_id: Mapped[str] = mapped_column(ForeignKey("test_targets.id"), nullable=False)
    suite_id: Mapped[str] = mapped_column(ForeignKey("test_suites.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="queued")
    defenses_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_by: Mapped[str] = mapped_column(String(120), default="local-admin")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TestResult(Base, Timestamped):
    __tablename__ = "test_results"
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id"), nullable=False)
    case_id: Mapped[str] = mapped_column(ForeignKey("test_cases.id"), nullable=False)
    outcome: Mapped[str] = mapped_column(String(30), nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    evaluable: Mapped[bool] = mapped_column(Boolean, default=True)
    response_excerpt: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(default=1.0)
    evaluation_method: Mapped[str] = mapped_column(String(80), default="deterministic-rubric")


class SecurityFinding(Base, Timestamped):
    __tablename__ = "security_findings"
    run_id: Mapped[str | None] = mapped_column(ForeignKey("test_runs.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(30), default="high")
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    scanner: Mapped[str] = mapped_column(String(80), default="bayora-rule-engine")
    verification_status: Mapped[str] = mapped_column(String(40), default="open")


class DefensePolicy(Base, Timestamped):
    __tablename__ = "defense_policies"
    key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    false_positive_note: Mapped[str] = mapped_column(Text, default="")


class DefenseEvent(Base, Timestamped):
    __tablename__ = "defense_events"
    policy_key: Mapped[str] = mapped_column(String(80), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)


class Alert(Base, Timestamped):
    __tablename__ = "alerts"
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    detection_method: Mapped[str] = mapped_column(String(120), nullable=False)
    recommended_response: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open")
    test_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class CodeUpload(Base, Timestamped):
    __tablename__ = "code_uploads"
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(40), default="received")
    exclusions: Mapped[list] = mapped_column(JSON, default=list)


class CodeScan(Base, Timestamped):
    __tablename__ = "code_scans"
    upload_id: Mapped[str] = mapped_column(ForeignKey("code_uploads.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="complete")
    scanners: Mapped[dict] = mapped_column(JSON, default=dict)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)


class PatchProposal(Base, Timestamped):
    __tablename__ = "patch_proposals"
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("security_findings.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="proposed")
    approved_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    backup_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)


class AuditLog(Base, Timestamped):
    __tablename__ = "audit_logs"
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

