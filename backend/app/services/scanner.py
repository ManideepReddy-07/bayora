import io
import json
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from .redaction import redact

MAX_FILES = 300
MAX_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
ALLOWED_NAMES = {"requirements.txt", "pyproject.toml", "dockerfile", "docker-compose.yml", "docker-compose.yaml"}


@dataclass
class ScanFinding:
    category: str
    severity: str
    confidence: str
    title: str
    evidence: str
    recommendation: str
    line: int | None = None
    scanner: str = "bayora-static-rules"


def tool_status() -> dict[str, str]:
    available = "available"
    unavailable = "not installed — Bayora rule-based analysis remains available"
    return {
        "bandit": available if shutil.which("bandit") else unavailable,
        "semgrep": available if shutil.which("semgrep") else unavailable,
        "pip-audit": available if shutil.which("pip-audit") else unavailable,
        "zap-baseline.py": available if shutil.which("zap-baseline.py") else unavailable,
    }


def scan_zip(raw: bytes) -> tuple[int, list[tuple[str, ScanFinding]], dict[str, str]]:
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        raise ValueError("Upload must be a ZIP archive")
    findings: list[tuple[str, ScanFinding]] = []
    source_files: dict[str, str] = {}
    file_count = 0
    total_size = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"Archive contains more than {MAX_FILES} files")
        for info in infos:
            path = PurePosixPath(info.filename)
            if info.is_dir():
                continue
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Archive path traversal is not permitted")
            total_size += info.file_size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Archive exceeds the safe expanded-size limit")
            name = path.name.lower()
            if path.suffix.lower() != ".py" and name not in ALLOWED_NAMES:
                continue
            file_count += 1
            content = archive.read(info).decode("utf-8", errors="replace")
            source_files[info.filename] = content
            findings.extend((info.filename, item) for item in _scan_text(content))
    scanner_results = tool_status()
    if shutil.which("bandit") and source_files:
        bandit_findings, bandit_status = _run_bandit(source_files)
        findings.extend(bandit_findings)
        scanner_results["bandit"] = bandit_status
    elif not source_files:
        scanner_results["bandit"] = "not run — no supported source files found"
    # Semgrep needs a locally managed rule configuration and pip-audit can
    # require vulnerability-feed access. They are displayed as available but
    # are not automatically invoked in this no-egress local prototype.
    if scanner_results["semgrep"] == "available":
        scanner_results["semgrep"] = "available — local rule configuration required"
    if scanner_results["pip-audit"] == "available":
        scanner_results["pip-audit"] = "available — not auto-run in no-egress mode"
    return file_count, findings, scanner_results


def _run_bandit(source_files: dict[str, str]) -> tuple[list[tuple[str, ScanFinding]], str]:
    try:
        with tempfile.TemporaryDirectory(prefix="bayora-bandit-") as temp_dir:
            root = Path(temp_dir)
            for name, content in source_files.items():
                target = root.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            completed = subprocess.run(
                ["bandit", "-r", str(root), "-f", "json", "-q"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
            # Bandit returns 1 when it finds issues, so parse both 0 and 1.
            if completed.returncode not in {0, 1}:
                return [], "error — Bandit returned a non-analysis status"
            payload = json.loads(completed.stdout or "{}")
            items: list[tuple[str, ScanFinding]] = []
            for issue in payload.get("results", []):
                filename = issue.get("filename", "<unknown>")
                try:
                    display_name = str(Path(filename).relative_to(root)).replace("\\", "/")
                except ValueError:
                    display_name = "<redacted-path>"
                items.append((display_name, ScanFinding(
                    category=f"bandit-{issue.get('test_id', 'finding').lower()}",
                    severity=str(issue.get("issue_severity", "medium")).lower(),
                    confidence=str(issue.get("issue_confidence", "medium")).lower(),
                    title=issue.get("test_name", "Bandit static-analysis finding").replace("_", " ").title(),
                    evidence=redact(issue.get("code", "")),
                    recommendation=issue.get("issue_text", "Review this Bandit finding in context and apply a least-privilege fix."),
                    line=issue.get("line_number"),
                    scanner="bandit",
                )))
            return items, f"completed — {len(items)} Bandit findings"
    except subprocess.TimeoutExpired:
        return [], "timed out after 15 seconds"
    except (OSError, json.JSONDecodeError):
        return [], "error — Bandit output could not be processed"


def _scan_text(content: str) -> list[ScanFinding]:
    found: list[ScanFinding] = []
    for number, line in enumerate(content.splitlines(), 1):
        normalized = line.lower()
        if "eval(" in normalized or "exec(" in normalized:
            found.append(ScanFinding("unsafe-execution", "high", "high", "Potential dynamic code execution", line.strip(), "Avoid eval/exec on untrusted data; use a strict parser or allowlisted operation.", number))
        if "shell=true" in normalized:
            found.append(ScanFinding("command-injection", "high", "medium", "Shell execution enabled", line.strip(), "Pass argument arrays with shell disabled and validate every input.", number))
        if any(token in normalized for token in ("api_key =", "password =", "secret =", "token =")) and not any(marker in normalized for marker in ("os.getenv", "environ", "example", "redacted")):
            found.append(ScanFinding("hardcoded-secret", "high", "medium", "Possible hardcoded secret", redact(line.strip()), "Move secrets to a secret manager or environment variable and rotate exposed values.", number))
    return found
