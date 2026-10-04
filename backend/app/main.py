import csv
import io
import ipaddress
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from .config import get_settings
from .database import Base, SessionLocal, engine, get_db
from .models import Alert, AuditLog, CodeScan, CodeUpload, DefenseEvent, DefensePolicy, PatchProposal, ProviderConfiguration, Role, SecurityFinding, TestCase, TestResult, TestRun, TestSuite, TestTarget, User
from .schemas import ChatRequest, LoginRequest, PatchApproval, PatchCreate, PolicyUpdate, ProviderCreate, ProviderUpdate, RunCreate, TargetCreate
from .security import DEMO_USERS, authenticate_demo_user, audit, create_session_token, current_role, require_roles
from .services.defense import inspect_request, inspect_response
from .services.providers import ProviderError, get_adapter
from .services.redaction import redact
from .services.redteam import DEFAULT_CASES, execute_run
from .services.scanner import scan_zip, tool_status

settings = get_settings()


def seed(db: Session) -> None:
    role_descriptions = {"administrator": "Platform configuration and approval", "red_team": "Authorized test execution", "blue_team": "Defense management", "viewer": "Read-only approved reports"}
    for name, description in role_descriptions.items():
        if not db.query(Role).filter_by(name=name).first():
            db.add(Role(name=name, description=description))
    for email, profile in DEMO_USERS.items():
        if not db.query(User).filter_by(email=email).first():
            db.add(User(email=email, display_name=profile["display_name"], role=profile["role"]))
    if not db.query(TestSuite).filter_by(name="Core AI Safety Regression").first():
        suite = TestSuite(name="Core AI Safety Regression", description="Deterministic synthetic tests for prompt injection, jailbreak resistance, and sensitive-data protection.", categories=["prompt_injection", "jailbreak_resistance", "sensitive_information"])
        db.add(suite)
        db.flush()
        for case in DEFAULT_CASES:
            db.add(TestCase(suite_id=suite.id, **case))
    if not db.query(TestTarget).filter_by(name="Built-in Demo Chatbot").first():
        db.add(TestTarget(name="Built-in Demo Chatbot", target_type="demo_chatbot", authorized=True, owner="bayora-local", status="approved"))
    if not db.query(ProviderConfiguration).filter_by(name="Built-in Mock").first():
        db.add(ProviderConfiguration(name="Built-in Mock", provider="mock", model="bayora-mock-v1", active=True, status="ready"))
    policies = [
        ("prompt_injection", "Prompt-injection detection", "Blocks instruction-override and system-prompt extraction patterns. May block legitimate prompt-engineering research.", "high"),
        ("sensitive_input", "Sensitive-data extraction guard", "Blocks requests seeking synthetic credentials or confidential records. May require an allowlisted workflow for support operations.", "high"),
        ("response_redaction", "Response secret redaction", "Redacts synthetic secret-shaped values in model output. It is a second layer, not a substitute for input controls.", "critical"),
        ("rate_limit", "Gateway request rate limit", "Limits each synthetic session to a bounded number of requests per minute. Very active legitimate sessions may need a higher approved limit.", "medium"),
    ]
    for key, name, description, severity in policies:
        if not db.query(DefensePolicy).filter_by(key=key).first():
            db.add(DefensePolicy(key=key, name=name, description=description, severity=severity, false_positive_note=description))
    # Privacy-preserving maintenance for development databases created by an
    # earlier version of the synthetic fixture rules. No test evidence needs a
    # literal secret value to remain useful.
    for finding in db.query(SecurityFinding).all():
        finding.evidence = redact(finding.evidence)
    for result in db.query(TestResult).all():
        result.response_excerpt = redact(result.response_excerpt)
    db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with next(get_db()) as db:
        seed(db)
    yield


app = FastAPI(title="Bayora API", version="0.1.0", description="Controlled AI security testing infrastructure", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code in {401, 403}:
        actor = request.headers.get("x-bayora-role", "anonymous")
        if actor not in {"administrator", "red_team", "blue_team", "viewer"}:
            actor = "anonymous"
        try:
            db = SessionLocal()
            audit(db, actor, "access_denied", "api_route", request.url.path, {"status_code": exc.status_code, "method": request.method})
            db.commit()
        except Exception:
            # A denial response must not fail open because audit storage is unavailable.
            pass
        finally:
            try:
                db.close()
            except UnboundLocalError:
                pass
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": str(exc.status_code), "message": exc.detail}})


@app.get("/health")
def health(db: Session = Depends(get_db)):
    return {"status": "healthy", "database": "connected", "version": app.version, "seeded": db.query(TestSuite).count() > 0}


@app.get("/health/live")
def liveness():
    return {"status": "alive", "version": app.version}


@app.get("/health/ready")
def readiness(db: Session = Depends(get_db)):
    db.query(TestSuite.id).limit(1).first()
    return {"status": "ready", "database": "connected"}


@app.get("/api/v1/auth/me")
def me(role: str = Depends(current_role)):
    return {"display_name": role.replace("_", " ").title(), "role": role, "demo_auth_header_enabled": settings.allow_demo_role_header, "note": "Use a signed Bearer session in shared environments; the local role header can be disabled with BAYORA_ALLOW_DEMO_ROLE_HEADER=false."}


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest):
    profile = authenticate_demo_user(payload.email, payload.password)
    if not profile:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_session_token(profile["email"], profile["role"])
    return {"access_token": token, "token_type": "bearer", "role": profile["role"], "display_name": profile["display_name"], "expires_in": 8 * 60 * 60}


@app.post("/api/v1/chat")
async def chat(payload: ChatRequest, db: Session = Depends(get_db), role: str = Depends(current_role)):
    prompt = payload.messages[-1].content
    decision = inspect_request(db, prompt, payload.session_id, payload.defense_enabled)
    if decision.blocked:
        audit(db, role, "chat_request_blocked", "chat", payload.session_id, {"policy": decision.policy_key})
        db.commit()
        return {"content": decision.reason, "blocked": True, "warning": decision.reason, "provider": "gateway", "model": "bayora-defense", "security": {"policy": decision.policy_key, "redacted": False}}
    provider = db.get(ProviderConfiguration, payload.provider_id) if payload.provider_id else db.query(ProviderConfiguration).filter_by(active=True).first()
    if not provider:
        raise HTTPException(400, "No active provider configuration")
    try:
        result = await get_adapter(provider.provider).generate_response([message.model_dump() for message in payload.messages], provider.model, {"base_url": provider.base_url, "secret_env_var": provider.secret_env_var, "timeout": settings.request_timeout_seconds, "weaknesses": payload.weaknesses})
    except ProviderError as exc:
        raise HTTPException(502, str(exc)) from exc
    content, redacted = inspect_response(db, result.content, payload.session_id, payload.defense_enabled)
    audit(db, role, "chat_response", "chat", payload.session_id, {"provider": provider.provider, "redacted": redacted})
    db.commit()
    return {**result.as_dict(), "content": content, "blocked": False, "warning": "Response redacted by gateway policy" if redacted else None, "security": {"policy": "response_redaction" if redacted else None, "redacted": redacted}}


def provider_public(item: ProviderConfiguration) -> dict:
    return {"id": item.id, "name": item.name, "provider": item.provider, "model": item.model, "base_url": item.base_url, "secret_env_var": item.secret_env_var, "has_server_secret_reference": bool(item.secret_env_var), "active": item.active, "status": item.status, "created_at": item.created_at}


@app.get("/api/v1/providers")
def providers(db: Session = Depends(get_db), _: str = Depends(current_role)):
    return [provider_public(item) for item in db.query(ProviderConfiguration).order_by(ProviderConfiguration.created_at.desc()).all()]


@app.post("/api/v1/providers", status_code=201)
def create_provider(payload: ProviderCreate, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator"))):
    if payload.active:
        db.query(ProviderConfiguration).update({ProviderConfiguration.active: False})
    item = ProviderConfiguration(**payload.model_dump())
    db.add(item)
    audit(db, role, "provider_configured", "provider", item.id, {"provider": item.provider, "secret_reference": bool(item.secret_env_var)})
    db.commit(); db.refresh(item)
    return provider_public(item)


@app.patch("/api/v1/providers/{provider_id}")
def update_provider(provider_id: str, payload: ProviderUpdate, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator"))):
    item = db.get(ProviderConfiguration, provider_id)
    if not item: raise HTTPException(404, "Provider configuration not found")
    updates = payload.model_dump(exclude_unset=True)
    if updates.get("active"):
        db.query(ProviderConfiguration).update({ProviderConfiguration.active: False})
    for key, value in updates.items(): setattr(item, key, value)
    audit(db, role, "provider_updated", "provider", item.id, {"fields": list(updates)})
    db.commit(); db.refresh(item)
    return provider_public(item)


@app.delete("/api/v1/providers/{provider_id}", status_code=204)
def delete_provider(provider_id: str, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator"))):
    item = db.get(ProviderConfiguration, provider_id)
    if not item: raise HTTPException(404, "Provider configuration not found")
    if item.provider == "mock": raise HTTPException(400, "The built-in mock provider cannot be removed")
    audit(db, role, "provider_removed", "provider", item.id)
    db.delete(item); db.commit()


@app.post("/api/v1/providers/{provider_id}/test")
async def test_provider(provider_id: str, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator"))):
    item = db.get(ProviderConfiguration, provider_id)
    if not item: raise HTTPException(404, "Provider configuration not found")
    try:
        response = await get_adapter(item.provider).generate_response([{"role": "user", "content": "Return a brief connectivity confirmation."}], item.model, {"base_url": item.base_url, "secret_env_var": item.secret_env_var, "timeout": settings.request_timeout_seconds})
        item.status = "ready"; audit(db, role, "provider_tested", "provider", item.id, {"status": "ready"}); db.commit()
        return {"ok": True, "message": "Connection succeeded", "response_preview": redact(response.content)[:160]}
    except ProviderError as exc:
        item.status = "error"; audit(db, role, "provider_tested", "provider", item.id, {"status": "error"}); db.commit()
        return JSONResponse(status_code=422, content={"ok": False, "message": str(exc)})


def is_safe_target_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host or host == "localhost":
        return False
    try:
        address = ipaddress.ip_address(host)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast)
    except ValueError:
        # No external target is executed by this prototype; DNS resolution is deliberately avoided.
        return True


@app.get("/api/v1/targets")
def targets(db: Session = Depends(get_db), _: str = Depends(current_role)):
    return [{"id": item.id, "name": item.name, "target_type": item.target_type, "base_url": item.base_url, "authorized": item.authorized, "status": item.status} for item in db.query(TestTarget).all()]


@app.post("/api/v1/targets", status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator"))):
    if payload.target_type == "authorized_api":
        if not payload.authorized: raise HTTPException(400, "Authorization confirmation is required for a live API target")
        if not payload.base_url or not is_safe_target_url(payload.base_url): raise HTTPException(400, "Target URL is not allowlisted for this local prototype")
    item = TestTarget(**payload.model_dump(), owner=role, status="approved" if payload.authorized else "pending")
    db.add(item); audit(db, role, "target_registered", "target", item.id, {"type": item.target_type, "authorized": item.authorized}); db.commit(); db.refresh(item)
    return {"id": item.id, "name": item.name, "authorized": item.authorized, "status": item.status}


@app.get("/api/v1/redteam/suites")
def suites(db: Session = Depends(get_db), _: str = Depends(current_role)):
    items = db.query(TestSuite).all()
    return [{"id": suite.id, "name": suite.name, "description": suite.description, "categories": suite.categories, "case_count": db.query(TestCase).filter_by(suite_id=suite.id).count()} for suite in items]


@app.post("/api/v1/redteam/runs", status_code=201)
async def start_run(payload: RunCreate, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator", "red_team"))):
    target = db.get(TestTarget, payload.target_id); suite = db.get(TestSuite, payload.suite_id)
    if not target or not suite: raise HTTPException(404, "Target or test suite not found")
    if not target.authorized or not payload.authorization_confirmed: raise HTTPException(400, "An authorized target and explicit confirmation are required")
    if target.target_type != "demo_chatbot": raise HTTPException(400, "This prototype only executes the isolated demo chatbot suite; registered external targets remain inventory-only.")
    cases_query = db.query(TestCase).filter_by(suite_id=suite.id)
    if payload.categories: cases_query = cases_query.filter(TestCase.category.in_(payload.categories))
    cases = cases_query.all()
    if not cases: raise HTTPException(400, "No test cases match the selected categories")
    run = TestRun(target_id=target.id, suite_id=suite.id, defenses_enabled=payload.defenses_enabled, authorized_by=role)
    db.add(run); db.flush(); audit(db, role, "redteam_run_started", "test_run", run.id, {"target": target.name, "defenses_enabled": payload.defenses_enabled})
    await execute_run(db, run, cases)
    audit(db, role, "redteam_run_completed", "test_run", run.id, run.metrics); db.commit(); db.refresh(run)
    return run_public(db, run, include_results=True)


def run_public(db: Session, run: TestRun, include_results: bool = False) -> dict:
    output = {"id": run.id, "target_id": run.target_id, "suite_id": run.suite_id, "status": run.status, "defenses_enabled": run.defenses_enabled, "metrics": run.metrics, "created_at": run.created_at, "completed_at": run.completed_at}
    if include_results:
        results = db.query(TestResult).filter_by(run_id=run.id).all()
        cases = {item.id: item for item in db.query(TestCase).all()}
        output["results"] = [{"id": item.id, "test_id": cases[item.case_id].test_id, "category": cases[item.case_id].category, "outcome": item.outcome, "blocked": item.blocked, "response_excerpt": item.response_excerpt, "evidence": item.evidence} for item in results]
        output["findings"] = findings_public(db.query(SecurityFinding).filter_by(run_id=run.id).all())
    return output


@app.get("/api/v1/redteam/runs")
def runs(limit: int = Query(default=20, ge=1, le=100), db: Session = Depends(get_db), _: str = Depends(current_role)):
    return [run_public(db, run) for run in db.query(TestRun).order_by(TestRun.created_at.desc()).limit(limit).all()]


@app.get("/api/v1/redteam/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db), _: str = Depends(current_role)):
    run = db.get(TestRun, run_id)
    if not run: raise HTTPException(404, "Test run not found")
    return run_public(db, run, include_results=True)


def findings_public(items: list[SecurityFinding]) -> list[dict]:
    return [{"id": item.id, "run_id": item.run_id, "title": item.title, "category": item.category, "severity": item.severity, "confidence": item.confidence, "explanation": item.explanation, "evidence": item.evidence, "recommendation": item.recommendation, "scanner": item.scanner, "verification_status": item.verification_status, "created_at": item.created_at} for item in items]


@app.get("/api/v1/findings")
def findings(db: Session = Depends(get_db), _: str = Depends(current_role)):
    return findings_public(db.query(SecurityFinding).order_by(SecurityFinding.created_at.desc()).all())


@app.get("/api/v1/blueteam/policies")
def policies(db: Session = Depends(get_db), _: str = Depends(current_role)):
    return [{"id": item.id, "key": item.key, "name": item.name, "description": item.description, "severity": item.severity, "enabled": item.enabled, "false_positive_note": item.false_positive_note} for item in db.query(DefensePolicy).all()]


@app.patch("/api/v1/blueteam/policies/{key}")
def set_policy(key: str, payload: PolicyUpdate, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator", "blue_team"))):
    item = db.query(DefensePolicy).filter_by(key=key).first()
    if not item: raise HTTPException(404, "Defense policy not found")
    item.enabled = payload.enabled; audit(db, role, "defense_policy_updated", "defense_policy", item.id, {"key": key, "enabled": payload.enabled}); db.commit()
    return {"key": item.key, "enabled": item.enabled}


@app.get("/api/v1/blueteam/events")
def events(limit: int = Query(default=30, ge=1, le=100), db: Session = Depends(get_db), _: str = Depends(require_roles("administrator", "blue_team"))):
    return [{"id": item.id, "policy_key": item.policy_key, "event_type": item.event_type, "severity": item.severity, "detail": item.detail, "action": item.action, "created_at": item.created_at} for item in db.query(DefenseEvent).order_by(DefenseEvent.created_at.desc()).limit(limit).all()]


@app.get("/api/v1/blueteam/alerts")
def alerts(db: Session = Depends(get_db), _: str = Depends(current_role)):
    return [{"id": item.id, "severity": item.severity, "category": item.category, "explanation": item.explanation, "detection_method": item.detection_method, "recommended_response": item.recommended_response, "status": item.status, "created_at": item.created_at} for item in db.query(Alert).order_by(Alert.created_at.desc()).limit(50).all()]


@app.post("/api/v1/patches", status_code=201)
def create_patch(payload: PatchCreate, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator", "blue_team"))):
    if payload.finding_id and not db.get(SecurityFinding, payload.finding_id): raise HTTPException(404, "Finding not found")
    item = PatchProposal(**payload.model_dump())
    db.add(item); audit(db, role, "patch_proposed", "patch", item.id, {"finding_id": item.finding_id}); db.commit(); db.refresh(item)
    return patch_public(item)


@app.get("/api/v1/patches")
def patches(db: Session = Depends(get_db), _: str = Depends(require_roles("administrator", "blue_team"))):
    return [patch_public(item) for item in db.query(PatchProposal).order_by(PatchProposal.created_at.desc()).all()]


def patch_public(item: PatchProposal) -> dict:
    return {"id": item.id, "finding_id": item.finding_id, "title": item.title, "diff": item.diff, "status": item.status, "approved_by": item.approved_by, "backup_reference": item.backup_reference, "created_at": item.created_at}


def suggested_diff(finding: SecurityFinding) -> str:
    templates = {
        "unsafe-execution": "--- a/<review-required>.py\n+++ b/<review-required>.py\n@@\n- result = eval(user_input)\n+ result = parse_allowlisted_input(user_input)\n",
        "command-injection": "--- a/<review-required>.py\n+++ b/<review-required>.py\n@@\n- subprocess.run(command, shell=True)\n+ subprocess.run([program, *validated_args], shell=False, check=True)\n",
        "hardcoded-secret": "--- a/<review-required>.py\n+++ b/<review-required>.py\n@@\n- SECRET = \"<redacted>\"\n+ SECRET = os.environ[\"APP_SECRET\"]\n",
        "prompt_injection": "--- a/gateway.py\n+++ b/gateway.py\n@@\n- return provider.generate(user_prompt)\n+ decision = inspect_request(user_prompt)\n+ if decision.blocked:\n+     return safe_block_response(decision)\n+ return provider.generate(user_prompt)\n",
        "sensitive_information": "--- a/gateway.py\n+++ b/gateway.py\n@@\n- return provider.generate(user_prompt)\n+ response = provider.generate(user_prompt)\n+ return redact_sensitive_response(response)\n",
    }
    return templates.get(finding.category, "--- a/<review-required>\n+++ b/<review-required>\n@@\n- # vulnerable behavior\n+ # add validated, least-privilege defense here\n")


@app.post("/api/v1/findings/{finding_id}/patch-proposal", status_code=201)
def generate_patch_proposal(finding_id: str, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator", "blue_team"))):
    finding = db.get(SecurityFinding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    item = PatchProposal(finding_id=finding.id, title=f"Proposed remediation: {finding.title}", diff=suggested_diff(finding))
    db.add(item)
    audit(db, role, "patch_generated", "patch", item.id, {"finding_id": finding.id, "review_required": True})
    db.commit(); db.refresh(item)
    return patch_public(item)


@app.post("/api/v1/patches/{patch_id}/approve")
def approve_patch(patch_id: str, _: PatchApproval, db: Session = Depends(get_db), role: str = Depends(require_roles("administrator"))):
    item = db.get(PatchProposal, patch_id)
    if not item: raise HTTPException(404, "Patch proposal not found")
    if item.status != "proposed": raise HTTPException(409, "Only proposed patches can be approved")
    # This prototype records approval only. It never overwrites uploaded source code.
    item.status = "approved_pending_manual_apply"; item.approved_by = role; item.backup_reference = f"manual-working-copy-{item.id[:8]}"
    audit(db, role, "patch_approved", "patch", item.id, {"manual_apply_required": True}); db.commit()
    return patch_public(item)


@app.post("/api/v1/code-analysis/upload")
async def code_upload(file: UploadFile = File(...), db: Session = Depends(get_db), role: str = Depends(require_roles("administrator", "red_team"))):
    if not file.filename or not file.filename.lower().endswith(".zip"): raise HTTPException(400, "Only ZIP source archives are accepted")
    raw = await file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes: raise HTTPException(413, "Upload exceeds the configured file-size limit")
    try:
        file_count, scan_findings, scanner_results = scan_zip(raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    upload = CodeUpload(filename=file.filename, file_count=file_count, size_bytes=len(raw), status="scanned")
    db.add(upload); db.flush()
    for path, finding in scan_findings:
        db.add(SecurityFinding(title=finding.title, category=finding.category, severity=finding.severity, confidence=finding.confidence, explanation=f"{finding.scanner} identified a potential issue at {path}:{finding.line}.", evidence=f"{path}:{finding.line or '?'} — {redact(finding.evidence)}", recommendation=finding.recommendation, scanner=finding.scanner))
    scan = CodeScan(upload_id=upload.id, scanners=scanner_results, finding_count=len(scan_findings))
    db.add(scan); audit(db, role, "code_archive_scanned", "code_upload", upload.id, {"files": file_count, "findings": len(scan_findings), "executed_code": False}); db.commit(); db.refresh(scan)
    return {"upload_id": upload.id, "scan_id": scan.id, "file_count": file_count, "finding_count": len(scan_findings), "tool_status": scan.scanners, "note": "Archive contents were parsed in memory; no uploaded code was executed."}


@app.get("/api/v1/code-analysis/tools")
def analysis_tools(_: str = Depends(current_role)):
    return tool_status()


@app.get("/api/v1/reports/{run_id}")
def report(run_id: str, format: str = Query(default="json", pattern="^(json|csv)$"), db: Session = Depends(get_db), _: str = Depends(current_role)):
    run = db.get(TestRun, run_id)
    if not run: raise HTTPException(404, "Test run not found")
    data = run_public(db, run, include_results=True)
    if format == "json": return data
    buffer = io.StringIO(); writer = csv.writer(buffer)
    writer.writerow(["test_id", "category", "outcome", "blocked", "response_excerpt"])
    for item in data["results"]: writer.writerow([item["test_id"], item["category"], item["outcome"], item["blocked"], item["response_excerpt"]])
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=bayora-report-{run_id[:8]}.csv"})


@app.get("/api/v1/overview")
def overview(db: Session = Depends(get_db), _: str = Depends(current_role)):
    runs = db.query(TestRun).filter_by(status="completed").all()
    metrics = [run.metrics or {} for run in runs]
    total_tests = sum(metric.get("total_tests", 0) for metric in metrics)
    blocked = sum(metric.get("blocked_attacks", 0) for metric in metrics)
    protection = sum(metric.get("passed_tests", 0) for metric in metrics)
    severity_rows = db.query(SecurityFinding.severity, func.count(SecurityFinding.id)).group_by(SecurityFinding.severity).all()
    outcomes = db.query(TestResult.outcome, func.count(TestResult.id)).group_by(TestResult.outcome).all()
    recent = [run_public(db, run) for run in db.query(TestRun).order_by(TestRun.created_at.desc()).limit(5).all()]
    return {"metrics": {"total_runs": len(runs), "total_tests": total_tests, "attack_block_rate": round(blocked / total_tests * 100, 1) if total_tests else 0, "sensitive_protection_rate": round(protection / total_tests * 100, 1) if total_tests else 0, "critical_findings": db.query(SecurityFinding).filter_by(severity="critical", verification_status="open").count(), "active_alerts": db.query(Alert).filter_by(status="open").count(), "connected_providers": db.query(ProviderConfiguration).filter_by(status="ready").count(), "defenses_enabled": db.query(DefensePolicy).filter_by(enabled=True).count()}, "findings_by_severity": [{"name": name, "value": value} for name, value in severity_rows], "attack_outcomes": [{"name": name, "value": value} for name, value in outcomes], "recent_runs": recent, "recent_findings": findings_public(db.query(SecurityFinding).order_by(SecurityFinding.created_at.desc()).limit(5).all()), "metric_note": "These metrics cover executed deterministic synthetic tests only; they are not a universal measure of security."}


@app.get("/api/v1/infrastructure")
def infrastructure(db: Session = Depends(get_db), _: str = Depends(require_roles("administrator"))):
    denied = db.query(AuditLog).filter(AuditLog.action.like("%denied%")).order_by(AuditLog.created_at.desc()).limit(10).all()
    recent_audit = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(12).all()
    return {"services": [{"name": "frontend", "status": "healthy", "boundary": "Browser client"}, {"name": "api", "status": "healthy", "boundary": "Role-checked API"}, {"name": "red-team-worker", "status": "ready", "boundary": "Demo target allowlist"}, {"name": "blue-monitor", "status": "healthy", "boundary": "Append-only event recording"}, {"name": "database", "status": "healthy", "boundary": "SQLite local development"}], "roles": {"administrator": ["configure", "approve", "audit"], "red_team": ["run authorized demo tests", "scan source archives"], "blue_team": ["manage defenses", "propose patches"], "viewer": ["view approved data"]}, "resource_limits": {"request_timeout_seconds": settings.request_timeout_seconds, "max_upload_bytes": settings.max_upload_bytes, "rate_limit_requests": settings.rate_limit_requests, "rate_limit_window_seconds": settings.rate_limit_window_seconds, "zip_max_files": 300, "zip_max_expanded_bytes": 10 * 1024 * 1024}, "recent_access_denied": [{"action": row.action, "created_at": row.created_at, "detail": row.detail} for row in denied], "recent_audit": [{"actor": row.actor, "action": row.action, "resource_type": row.resource_type, "created_at": row.created_at} for row in recent_audit], "isolation_note": "Docker Compose is a local demonstration boundary, not a hardened production sandbox. External live scans are intentionally not executed by this prototype."}


@app.get("/api/v1/audit")
def audit_logs(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db), _: str = Depends(require_roles("administrator"))):
    return [{"id": item.id, "actor": item.actor, "action": item.action, "resource_type": item.resource_type, "resource_id": item.resource_id, "detail": item.detail, "created_at": item.created_at} for item in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()]
