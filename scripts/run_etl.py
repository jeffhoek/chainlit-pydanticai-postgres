"""ETL orchestrator for the scheduled refresh job.

Runs each loader in-process and collects a structured LoaderReport (summary line
+ metrics), then emails a results summary via Azure Communication Services.
Running in-process (rather than as subprocesses) streams each loader's logs live
to the job log and lets the email render real metrics instead of grepping stdout.

The loaders are independent — the full NVD incremental writes nvd_vulnerabilities,
the KEV catalog writes kev_vulnerabilities, and EPSS writes epss_scores — so every
step runs regardless of whether another fails, and their order doesn't matter.
EPSS is listed last only to keep the long-pole NVD sync first.

Email is best-effort and optional: if the ACS_* / ETL_EMAIL_TO env vars are unset
(e.g. local runs), the email step is skipped. The process exit code reflects the
ETL outcome only — a failed email never masks a successful sync, and any failed
loader exits non-zero so the platform records the failure.

Env:
    ACS_ENDPOINT    Azure Communication Services endpoint (https://<host>)
    ACS_SENDER      Verified sender address (e.g. donotreply@<domain>.azurecomm.net)
    ETL_EMAIL_TO    Comma-separated recipient address(es)
    AZURE_CLIENT_ID Client ID of the user-assigned managed identity (for auth)
"""

import asyncio
import contextlib
import importlib
import json
import os
import sys
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path

# Make `scripts.<loader>` importable whether run as `python scripts/run_etl.py`
# (sys.path[0] is scripts/) or imported as scripts.run_etl (tests).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# (label, "module:attr") — each attr is an async () -> LoaderReport entrypoint,
# resolved lazily so importing this module stays free of the data-stack deps.
STEPS: list[tuple[str, str]] = [
    ("NVD full incremental", "scripts.load_nvd_full:run_incremental"),
    ("KEV catalog", "scripts.load_kev:run"),
    ("EPSS scores", "scripts.load_epss:run"),
]


def _fmt_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s"


def _resolve(target: str):
    """Import 'module:attr' lazily and return the attribute (a coroutine fn)."""
    module_name, _, attr = target.partition(":")
    return getattr(importlib.import_module(module_name), attr)


def run_step(label: str, target: str) -> dict:
    """Run one loader in-process, returning its report, timing, and any error.

    The loader's own prints stream straight to the job log. A raised exception is
    caught here so one loader's failure can't abort the others; the traceback still
    reaches the log and the step is recorded as failed.
    """
    print(f"\n=== {label} ===", flush=True)
    started = time.time()
    try:
        report = asyncio.run(_resolve(target)())
        ok, summary, metrics, error = True, report.summary, report.metrics, None
    except Exception as exc:
        traceback.print_exc()
        ok, summary, metrics, error = False, "", {}, f"{type(exc).__name__}: {exc}"
    return {
        "label": label,
        "ok": ok,
        "elapsed": time.time() - started,
        "summary": summary,
        "metrics": metrics,
        "error": error,
    }


def run_pipeline(steps: list[tuple[str, str]], runner=run_step) -> list[dict]:
    """Run every step, returning one result dict per step.

    The loaders are independent (NVD full -> nvd_vulnerabilities, KEV ->
    kev_vulnerabilities, EPSS -> epss_scores), so a failure in one must not skip
    the others — all always run and the summary reports each outcome.
    """
    return [runner(label, target) for label, target in steps]


def build_email(results: list[dict], total_elapsed: float) -> tuple[str, str]:
    """Return (subject, plain-text body) summarizing the run."""
    all_ok = all(r["ok"] for r in results)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    status = "SUCCESS" if all_ok else "FAILED"
    subject = f"[{status}] NVD/KEV ETL — {stamp}"

    lines = [f"ETL run {status} at {stamp} (total {_fmt_duration(total_elapsed)})", ""]
    for r in results:
        mark = "OK  " if r["ok"] else "FAIL"
        detail = r["summary"] if r["ok"] else (r["error"] or "failed")
        lines.append(f"[{mark}] {r['label']} ({_fmt_duration(r['elapsed'])}) — {detail}")
    return subject, "\n".join(lines)


def send_email(subject: str, body: str) -> None:
    """Send the summary via Azure Communication Services (best-effort)."""
    endpoint = os.getenv("ACS_ENDPOINT")
    sender = os.getenv("ACS_SENDER")
    recipients = os.getenv("ETL_EMAIL_TO")
    if not (endpoint and sender and recipients):
        print("Email not configured (ACS_ENDPOINT/ACS_SENDER/ETL_EMAIL_TO unset) — skipping.")
        return

    try:
        from azure.communication.email import EmailClient
        from azure.identity import DefaultAzureCredential

        client = EmailClient(endpoint, DefaultAzureCredential())
        message = {
            "senderAddress": sender,
            "recipients": {"to": [{"address": a.strip()} for a in recipients.split(",") if a.strip()]},
            "content": {"subject": subject, "plainText": body},
        }
        poller = client.begin_send(message)
        result = poller.result()
        print(f"Email sent (status: {result['status']}).")
    except Exception as exc:  # never let email failure mask the ETL result
        print(f"WARNING: failed to send results email: {exc}")


def record_run(results: list[dict], total_elapsed: float) -> None:
    """Persist the run to etl_runs (best-effort; never masks the ETL result).

    Mirrors send_email()'s contract: any failure is logged and swallowed so a DB
    error can't change the process exit code — the ETL outcome stays authoritative.
    The write is unconditional (no env flag): wherever the ETL runs the loaders
    already need a write-capable DSN, so there's no skip gap to gate.
    """
    status = "SUCCESS" if all(r["ok"] for r in results) else "FAILED"
    try:
        import asyncpg

        from config import settings

        async def _insert():
            conn = await asyncpg.connect(dsn=settings.get_database_dsn())
            try:
                await conn.execute(
                    "INSERT INTO etl_runs (status, total_elapsed, results) VALUES ($1, $2, $3::jsonb)",
                    status,
                    round(total_elapsed, 2),
                    json.dumps(results),
                )
            finally:
                await conn.close()

        asyncio.run(_insert())
        print("ETL run recorded to etl_runs.")
    except Exception as exc:  # never let a DB error mask the ETL result
        print(f"WARNING: failed to record ETL run: {exc}")


def main() -> int:
    # Line-buffer stdout so loader logs stream live to the job log (not block-buffered).
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(line_buffering=True)

    overall_start = time.time()
    results = run_pipeline(STEPS)
    total_elapsed = time.time() - overall_start

    subject, body = build_email(results, total_elapsed)
    print(f"\n{subject}\n{body}")
    send_email(subject, body)
    record_run(results, total_elapsed)

    return 0 if results and all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
