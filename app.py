import os
import sys
import logging
import datetime
import time
import inspect
import uuid
import threading
import asyncio
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_cors import CORS
import io

# Root application modules

import re
from app.core.config import settings
from app.core.subscription_discovery import SubscriptionDiscoveryService
from app.core.authentication import AzureAuthService
from app.core.azure_client_factory import azure_client_factory
from app.assessments.registry import assessment_registry
from app.assessments.base import AssessmentContext
from app.intelligence.aggregation import AssessmentAggregator
from app.schemas.subscription import SubscriptionModel
from app.schemas.assessment import AssessmentStatus
from app.utils.validators import is_valid_guid
from app.reports.pdf.security_pdf import generate_security_pdf
from app.reports.pdf.cost_pdf import generate_cost_pdf
from app.reports.pdf.combined_pdf import generate_combined_pdf
from app.reports.excel.security_excel import generate_security_excel
from app.reports.excel.cost_excel import generate_cost_excel
from app.reports.excel.combined_excel import generate_combined_excel
from app.reports.pdf.single_pdf import generate_single_pdf
from app.reports.excel.single_excel import generate_single_excel

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# In-Memory Store (Zero database, zero permanent credential or report storage)
CONNECTIONS = {}
JOBS = {}
REPORTS = {}
STORE_LOCK = threading.Lock()

def run_async(coro):
    """Executes an async coroutine from Flask sync route handlers cleanly."""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    """Lightweight endpoint for keep-alive cron jobs (e.g. cron-job.org, UptimeRobot)."""
    return jsonify({
        "status": "healthy",
        "service": "azure-finsecops-platform",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }), 200

@app.route("/.well-known/appspecific/com.chrome.devtools.json", methods=["GET"])
def chrome_devtools_json():
    return jsonify({})

# -------------------------------------------------------------
# CONNECTION ENDPOINTS
# -------------------------------------------------------------
@app.route("/api/connection/connect", methods=["POST"])
def connect():
    data = request.get_json() or {}
    workspace_name = (data.get("workspace_name") or "").strip()
    tenant_id = data.get("tenant_id", "").strip()
    client_id = data.get("client_id", "").strip()
    client_secret = data.get("client_secret", "").strip()
    target_subscription_ids = data.get("target_subscription_ids")

    if not workspace_name:
        workspace_name = f"Tenant ({tenant_id[:8]})" if tenant_id else "Azure Workspace"

    if not tenant_id or not client_id or not client_secret:
        return jsonify({"detail": "Azure Tenant ID, Client ID, and Client Secret are required."}), 400

    if not is_valid_guid(tenant_id) or not is_valid_guid(client_id):
        return jsonify({"detail": "Tenant ID and Client ID must be valid GUIDs."}), 400

    target_tags_str = (data.get("target_tags") or "").strip()
    all_tags = [t.strip() for t in target_tags_str.split(",") if t.strip()] if target_tags_str else []
    prod_tags = [t for t in all_tags if re.search(r"(?i)(prod|production|live|prd)", t)]
    test_tags = [t for t in all_tags if re.search(r"(?i)(test|testing|qa|uat|staging|stage|sandbox|dev|development|nonprod)", t)]

    # Clean target subscription IDs if provided
    clean_targets = None
    if target_subscription_ids and isinstance(target_subscription_ids, list):
        clean_targets = [s.strip() for s in target_subscription_ids if s and s.strip()]
        if not clean_targets:
            clean_targets = None

    try:
        subs = run_async(SubscriptionDiscoveryService.discover_subscriptions(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            target_subscription_ids=clean_targets
        ))
    except Exception as ex:
        return jsonify({"detail": f"Azure authentication or subscription discovery failed: {str(ex)}"}), 401

    if clean_targets and not subs:
        return jsonify({"detail": "None of the specified subscription IDs could be accessed with this Service Principal. Please check subscription IDs and permissions."}), 400

    if not subs or len(subs) == 0:
        return jsonify({"detail": "No accessible subscriptions found in this Azure tenant for the provided Service Principal. Ensure 'Reader' role is assigned on at least one subscription."}), 400

    detected_currency = None
    if subs and len(subs) > 0:
        try:
            from app.azure.cost_management import CostManagementAdapter
            probe_client = run_async(azure_client_factory.get_client_for_session(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            ))
            first_sub_id = subs[0].subscription_id if hasattr(subs[0], "subscription_id") else subs[0].get("subscription_id")
            queried_curr = run_async(CostManagementAdapter.get_subscription_currency(probe_client, first_sub_id))
            if queried_curr:
                detected_currency = queried_curr.upper()
        except Exception as ex:
            logging.getLogger("azure_finsecops").warning(f"Could not probe currency on connect: {ex}")

    conn_id = str(uuid.uuid4())
    with STORE_LOCK:
        CONNECTIONS[conn_id] = {
            "connection_id": conn_id,
            "workspace_name": workspace_name,
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret,
            "subscriptions": subs,
            "currency": detected_currency,
            "target_tags": all_tags,
            "prod_tags": prod_tags,
            "test_tags": test_tags,
            "target_tags_str": target_tags_str,
            "connected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    return jsonify({
        "connection_id": conn_id,
        "workspace_name": workspace_name,
        "tenant_id": tenant_id,
        "accessible_subscriptions_count": len(subs),
        "status": "Connected",
        "currency": detected_currency,
        "target_tags": target_tags_str
    })

@app.route("/api/connection/status/<connection_id>", methods=["GET"])
def connection_status(connection_id):
    with STORE_LOCK:
        conn = CONNECTIONS.get(connection_id)
    if not conn:
        return jsonify({"detail": "Connection session not found."}), 404
    return jsonify({
        "connection_id": conn["connection_id"],
        "workspace_name": conn["workspace_name"],
        "tenant_id": conn["tenant_id"],
        "subscription_count": len(conn.get("subscriptions", [])),
        "currency": conn.get("currency", "USD"),
        "target_tags": conn.get("target_tags_str", "prod, test, dev, staging")
    })

@app.route("/api/connection/<connection_id>", methods=["DELETE"])
def disconnect(connection_id):
    with STORE_LOCK:
        if connection_id in CONNECTIONS:
            CONNECTIONS[connection_id]["client_secret"] = None
            del CONNECTIONS[connection_id]
            return jsonify({"success": True, "message": "Disconnected."})
    return jsonify({"detail": "Connection not found."}), 404

@app.route("/api/subscriptions/validate", methods=["POST"])
def validate_subscription():
    data = request.get_json() or {}
    tenant_id = data.get("tenant_id", "").strip()
    client_id = data.get("client_id", "").strip()
    client_secret = data.get("client_secret", "").strip()
    subscription_id = data.get("subscription_id", "").strip()

    if not is_valid_guid(tenant_id) or not is_valid_guid(client_id):
        return jsonify({
            "valid": False,
            "subscription_id": subscription_id,
            "error": "Tenant ID and Client ID must be valid GUIDs."
        })

    result = run_async(SubscriptionDiscoveryService.validate_single_subscription(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        subscription_id=subscription_id
    ))
    return jsonify(result)

@app.route("/api/subscriptions/<connection_id>", methods=["GET"])
def get_subscriptions(connection_id):
    with STORE_LOCK:
        conn = CONNECTIONS.get(connection_id)
    if not conn:
        return jsonify({"detail": "Connection session not found."}), 404

    subs = conn.get("subscriptions", [])
    sub_dicts = [s.model_dump() if hasattr(s, "model_dump") else s.__dict__ for s in subs]
    return jsonify({"total_count": len(subs), "subscriptions": sub_dicts})

# -------------------------------------------------------------
# ASSESSMENT CATALOGUE ENDPOINTS
# -------------------------------------------------------------
@app.route("/api/assessments", methods=["GET"])
def list_assessments():
    defs = [d.model_dump() for d in assessment_registry.get_all_definitions()]
    return jsonify(defs)

@app.route("/api/assessments/security", methods=["GET"])
def list_security_assessments():
    defs = [d.model_dump() for d in assessment_registry.get_security_definitions()]
    return jsonify(defs)

@app.route("/api/assessments/cost", methods=["GET"])
def list_cost_assessments():
    defs = [d.model_dump() for d in assessment_registry.get_cost_definitions()]
    return jsonify(defs)

# -------------------------------------------------------------
# ASYNC JOB EXECUTION ENGINE
# -------------------------------------------------------------
def background_assessment_runner(job_id, conn, target_assessments):
    """Runs the selected assessments in a background thread using a dedicated asyncio event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_assessments_async(job_id, conn, target_assessments))
    finally:
        loop.close()

async def _run_assessments_async(job_id, conn, target_assessments):
    try:
        client = None
        try:
            client = await azure_client_factory.get_client_for_session(
                tenant_id=conn["tenant_id"],
                client_id=conn["client_id"],
                client_secret=conn.get("client_secret")
            )
        except Exception as ex:
            with STORE_LOCK:
                if job_id in JOBS:
                    JOBS[job_id]["status"] = "Failed"
                    JOBS[job_id]["progress"]["status"] = "Failed"
                    JOBS[job_id]["progress"]["recent_logs"].append({
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "level": "ERROR",
                        "message": f"Azure ARM client failed: {str(ex)}"
                    })
            return

        ctx = AssessmentContext(
            connection_id=conn["connection_id"],
            workspace_name=conn["workspace_name"],
            tenant_id=conn["tenant_id"],
            subscriptions=conn.get("subscriptions", []),
            client=client,
            currency=conn.get("currency", "USD"),
            target_tags=conn.get("target_tags", []),
            prod_tags=conn.get("prod_tags", []),
            test_tags=conn.get("test_tags", [])
        )

        results = {}
        completed_count = 0
        failed_count = 0
        total_count = len(target_assessments)
        start_time = datetime.datetime.now()

        for idx, ass in enumerate(target_assessments):
            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            with STORE_LOCK:
                if job_id in JOBS:
                    prog = JOBS[job_id]["progress"]
                    prog["current_assessment"] = f"[{ass.code}] {ass.name}"
                    prog["current_subscription"] = (
                        ctx.subscriptions[idx % len(ctx.subscriptions)].display_name
                        if ctx.subscriptions else "Global Scope"
                    )
                    prog["running_assessments"] = 1
                    prog["pending_assessments"] = max(0, total_count - completed_count - failed_count)
                    prog["duration_seconds"] = round((datetime.datetime.now() - start_time).total_seconds(), 1)
                    prog["recent_logs"].append({
                        "timestamp": now_str,
                        "level": "INFO",
                        "message": f"Evaluating [{ass.code}] {ass.name}..."
                    })
                    prog["recent_logs"] = prog["recent_logs"][-50:]

            try:
                res = await ass.run(ctx)
                results[ass.assessment_id] = res
                completed_count += 1
                log_lvl = "SUCCESS" if res.findings_count > 0 else "INFO"
                log_msg = (
                    f"[{ass.code}] Completed: {res.findings_count} finding(s) detected."
                    if res.findings_count > 0 else f"[{ass.code}] Completed: Clean baseline, 0 issues."
                )
            except Exception as ex:
                failed_count += 1
                res = ass.create_empty_result(AssessmentStatus.FAILED)
                res.errors.append(str(ex))
                results[ass.assessment_id] = res
                log_lvl = "ERROR"
                log_msg = f"[{ass.code}] Assessment error: {str(ex)}"

            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            with STORE_LOCK:
                if job_id in JOBS:
                    prog = JOBS[job_id]["progress"]
                    prog["completed_assessments"] = completed_count
                    prog["failed_assessments"] = failed_count
                    prog["pending_assessments"] = max(0, total_count - completed_count - failed_count)
                    prog["progress_percentage"] = round(((completed_count + failed_count) / total_count) * 100, 1)
                    prog["duration_seconds"] = round((datetime.datetime.now() - start_time).total_seconds(), 1)
                    prog["recent_logs"].append({
                        "timestamp": now_str,
                        "level": log_lvl,
                        "message": log_msg
                    })
                    prog["recent_logs"] = prog["recent_logs"][-50:]

        summary = AssessmentAggregator.aggregate_results(results, default_currency=conn.get("currency", "USD"))

        final_status = "Completed"
        if failed_count > 0:
            final_status = "Failed" if failed_count == total_count else "Completed with Warnings"

        with STORE_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["status"] = final_status
                prog = JOBS[job_id]["progress"]
                prog["status"] = final_status
                prog["running_assessments"] = 0
                prog["current_assessment"] = "All assessments finished."
                prog["current_subscription"] = "Scan Completed."
                prog["progress_percentage"] = 100.0
                prog["duration_seconds"] = round((datetime.datetime.now() - start_time).total_seconds(), 1)
                prog["recent_logs"].append({
                    "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                    "level": "SUCCESS",
                    "message": f"Scan completed. {summary['total_findings']} total finding(s) identified across {total_count} modules."
                })
                JOBS[job_id]["results"] = results
                JOBS[job_id]["summary"] = summary
                if conn.get("connection_id") in CONNECTIONS:
                    CONNECTIONS[conn["connection_id"]].setdefault("cumulative_results", {}).update(results)
                    all_acc = CONNECTIONS[conn["connection_id"]]["cumulative_results"]
                    full_summary = AssessmentAggregator.aggregate_results(
                        all_acc, default_currency=conn.get("currency", "USD")
                    )
                    CONNECTIONS[conn["connection_id"]]["cumulative_summary"] = full_summary
                    JOBS[job_id]["summary"] = full_summary
    except Exception as e:
        import traceback
        traceback.print_exc()
        with STORE_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["status"] = "Failed"
                JOBS[job_id]["progress"]["status"] = "Failed"
                JOBS[job_id]["progress"]["recent_logs"].append({
                    "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                    "level": "ERROR",
                    "message": f"Runner thread fatal error: {str(e)}"
                })

def launch_job(connection_id, scope="all", single_assessment_id=None):
    with STORE_LOCK:
        conn = CONNECTIONS.get(connection_id)
    if not conn:
        raise ValueError("Active connection session not found.")

    if single_assessment_id:
        ass = assessment_registry.get_assessment(single_assessment_id)
        if not ass:
            raise ValueError(f"Assessment '{single_assessment_id}' not found.")
        target_assessments = [ass]
    elif scope == "security":
        target_assessments = assessment_registry.get_security_assessments()
    elif scope == "cost":
        target_assessments = assessment_registry.get_cost_assessments()
    else:
        target_assessments = assessment_registry.get_all_assessments()

    job_id = str(uuid.uuid4())
    now_str = datetime.datetime.now().strftime("%H:%M:%S")

    job_data = {
        "job_id": job_id,
        "connection_id": connection_id,
        "scope": scope if not single_assessment_id else single_assessment_id,
        "status": "Running",
        "progress": {
            "job_id": job_id,
            "status": "Running",
            "scope": scope,
            "total_assessments": len(target_assessments),
            "completed_assessments": 0,
            "running_assessments": 1,
            "pending_assessments": len(target_assessments),
            "failed_assessments": 0,
            "current_subscription": "Initializing context...",
            "current_assessment": "Starting assessment job...",
            "progress_percentage": 0.0,
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "duration_seconds": 0.0,
            "recent_logs": [
                {
                    "timestamp": now_str,
                    "level": "INFO",
                    "message": f"Assessment job registered for scope '{scope}' with {len(target_assessments)} modules."
                }
            ]
        },
        "results": {},
        "summary": {}
    }

    with STORE_LOCK:
        JOBS[job_id] = job_data

    thread = threading.Thread(
        target=background_assessment_runner,
        args=(job_id, conn, target_assessments),
        daemon=True
    )
    thread.start()
    return job_id

@app.route("/api/assessments/run-all", methods=["POST"])
def run_all():
    data = request.get_json() or {}
    conn_id = data.get("connection_id")
    try:
        j_id = launch_job(conn_id, scope="all")
        return jsonify({"job_id": j_id, "status": "Running", "scope": "all"})
    except Exception as ex:
        return jsonify({"detail": str(ex)}), 400

@app.route("/api/assessments/run-security", methods=["POST"])
def run_security():
    data = request.get_json() or {}
    conn_id = data.get("connection_id")
    try:
        j_id = launch_job(conn_id, scope="security")
        return jsonify({"job_id": j_id, "status": "Running", "scope": "security"})
    except Exception as ex:
        return jsonify({"detail": str(ex)}), 400

@app.route("/api/assessments/run-cost", methods=["POST"])
def run_cost():
    data = request.get_json() or {}
    conn_id = data.get("connection_id")
    try:
        j_id = launch_job(conn_id, scope="cost")
        return jsonify({"job_id": j_id, "status": "Running", "scope": "cost"})
    except Exception as ex:
        return jsonify({"detail": str(ex)}), 400

@app.route("/api/assessments/<assessment_id>/run", methods=["POST"])
def run_single(assessment_id):
    data = request.get_json() or {}
    conn_id = data.get("connection_id")
    try:
        j_id = launch_job(conn_id, single_assessment_id=assessment_id)
        return jsonify({"job_id": j_id, "status": "Running", "assessment_id": assessment_id})
    except Exception as ex:
        return jsonify({"detail": str(ex)}), 400

@app.route("/api/jobs/<job_id>", methods=["GET"])
def get_job_progress(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"detail": "Job not found."}), 404
    return jsonify(job["progress"])

@app.route("/api/jobs/<job_id>/results", methods=["GET"])
def get_job_results(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"detail": "Job not found."}), 404

    # Convert results objects to serializable dicts
    serialized_results = {}
    for aid, res in job.get("results", {}).items():
        if hasattr(res, "model_dump"):
            serialized_results[aid] = res.model_dump(mode="json")
        elif hasattr(res, "__dict__"):
            d = dict(res.__dict__)
            if "findings" in d:
                d["findings"] = [f.model_dump(mode="json") if hasattr(f, "model_dump") else f.__dict__ for f in d["findings"]]
            serialized_results[aid] = d

    return jsonify({
        "job_id": job["job_id"],
        "status": job["status"],
        "progress": job["progress"],
        "summary": job.get("summary", {}),
        "results": serialized_results
    })

# -------------------------------------------------------------
# REPORT GENERATION & DOWNLOAD
# -------------------------------------------------------------
@app.route("/api/reports/security/pdf/<job_id>", methods=["POST"])
def create_sec_pdf(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
        conn = CONNECTIONS.get(job["connection_id"]) if job else None

    if not job or not conn:
        return jsonify({"detail": "Job not found."}), 404

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{conn['workspace_name'].replace(' ', '_')}_Security_Assessment_Report_{date_str}.pdf"

    pdf_bytes = generate_security_pdf(job, conn["workspace_name"], conn["tenant_id"])
    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": pdf_bytes,
            "content_type": "application/pdf"
        }

    return jsonify({"report_id": report_id, "filename": filename, "download_url": f"/api/reports/download/{report_id}"})

@app.route("/api/reports/security/excel/<job_id>", methods=["POST"])
def create_sec_excel(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
        conn = CONNECTIONS.get(job["connection_id"]) if job else None

    if not job or not conn:
        return jsonify({"detail": "Job not found."}), 404

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{conn['workspace_name'].replace(' ', '_')}_Security_Assessment_Report_{date_str}.xlsx"

    xlsx_bytes = generate_security_excel(job, conn["workspace_name"], conn["tenant_id"])
    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": xlsx_bytes,
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }

    return jsonify({"report_id": report_id, "filename": filename, "download_url": f"/api/reports/download/{report_id}"})

@app.route("/api/reports/cost/pdf/<job_id>", methods=["POST"])
def create_cost_pdf_route(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
        conn = CONNECTIONS.get(job["connection_id"]) if job else None

    if not job or not conn:
        return jsonify({"detail": "Job not found."}), 404

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{conn['workspace_name'].replace(' ', '_')}_Cost_Assessment_Report_{date_str}.pdf"

    pdf_bytes = generate_cost_pdf(job, conn["workspace_name"], conn["tenant_id"])
    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": pdf_bytes,
            "content_type": "application/pdf"
        }

    return jsonify({"report_id": report_id, "filename": filename, "download_url": f"/api/reports/download/{report_id}"})

@app.route("/api/reports/cost/excel/<job_id>", methods=["POST"])
def create_cost_excel_route(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
        conn = CONNECTIONS.get(job["connection_id"]) if job else None

    if not job or not conn:
        return jsonify({"detail": "Job not found."}), 404

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{conn['workspace_name'].replace(' ', '_')}_Cost_Assessment_Report_{date_str}.xlsx"

    xlsx_bytes = generate_cost_excel(job, conn["workspace_name"], conn["tenant_id"])
    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": xlsx_bytes,
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }

    return jsonify({"report_id": report_id, "filename": filename, "download_url": f"/api/reports/download/{report_id}"})

@app.route("/api/reports/combined/pdf/<job_id>", methods=["POST"])
def create_combined_pdf_route(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
        conn = CONNECTIONS.get(job["connection_id"]) if job else None

    if not job or not conn:
        return jsonify({"detail": "Job not found."}), 404

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{conn['workspace_name'].replace(' ', '_')}_Security_and_Cost_Assessment_Report_{date_str}.pdf"

    pdf_bytes = generate_combined_pdf(job, conn["workspace_name"], conn["tenant_id"])
    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": pdf_bytes,
            "content_type": "application/pdf"
        }

    return jsonify({"report_id": report_id, "filename": filename, "download_url": f"/api/reports/download/{report_id}"})

@app.route("/api/reports/combined/excel/<job_id>", methods=["POST"])
def create_combined_excel_route(job_id):
    with STORE_LOCK:
        job = JOBS.get(job_id)
        conn = CONNECTIONS.get(job["connection_id"]) if job else None

    if not job or not conn:
        return jsonify({"detail": "Job not found."}), 404

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{conn['workspace_name'].replace(' ', '_')}_Security_and_Cost_Assessment_Report_{date_str}.xlsx"

    xlsx_bytes = generate_combined_excel(job, conn["workspace_name"], conn["tenant_id"])
    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": xlsx_bytes,
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }

    return jsonify({"report_id": report_id, "filename": filename, "download_url": f"/api/reports/download/{report_id}"})

@app.route("/api/reports/single/<format_type>/<assessment_id>", methods=["POST"])
def create_single_report_route(format_type, assessment_id):
    ass_def = assessment_registry.get_assessment(assessment_id)
    if not ass_def:
        return jsonify({"detail": f"Assessment module '{assessment_id}' not found."}), 404

    data = request.get_json() or {}
    conn_id = data.get("connection_id")
    with STORE_LOCK:
        conn = CONNECTIONS.get(conn_id) if conn_id else None
        if not conn and CONNECTIONS:
            conn = next(iter(CONNECTIONS.values()))

    ws_name = conn.get("workspace_name", "Workspace") if conn else "Workspace"
    tenant_id = conn.get("tenant_id", "") if conn else ""

    # Fetch assessment findings from payload or cumulative results in connection or JOBS
    res_data = {}
    if data.get("results") and isinstance(data["results"], dict):
        res_data = data["results"].get(assessment_id, {})

    if not res_data and conn and conn.get("cumulative_results"):
        res_data = conn["cumulative_results"].get(assessment_id, {})

    if not res_data:
        with STORE_LOCK:
            for job in JOBS.values():
                if job.get("results") and assessment_id in job["results"]:
                    res_data = job["results"][assessment_id]
                    break

    code = getattr(ass_def, "code", "ASS")
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    safe_name = ass_def.name.replace(" ", "_").replace("/", "-")

    fmt = format_type.lower()
    if fmt == "pdf":
        filename = f"{ws_name.replace(' ', '_')}_{code}_{safe_name}_{date_str}.pdf"
        file_bytes = generate_single_pdf(ass_def, res_data, ws_name, tenant_id)
        content_type = "application/pdf"
    elif fmt in ["excel", "xlsx"]:
        filename = f"{ws_name.replace(' ', '_')}_{code}_{safe_name}_{date_str}.xlsx"
        file_bytes = generate_single_excel(ass_def, res_data, ws_name, tenant_id)
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    else:
        return jsonify({"detail": f"Unsupported format '{format_type}'. Use 'pdf' or 'excel'."}), 400

    report_id = str(uuid.uuid4())
    with STORE_LOCK:
        REPORTS[report_id] = {
            "filename": filename,
            "bytes": file_bytes,
            "content_type": content_type
        }

    return jsonify({
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    })

@app.route("/api/reports/download/<report_id>", methods=["GET"])
def download_report(report_id):
    with STORE_LOCK:
        rep = REPORTS.get(report_id)
    if not rep:
        return "Report not found or expired.", 404

    return send_file(
        io.BytesIO(rep["bytes"]),
        mimetype=rep["content_type"],
        as_attachment=True,
        download_name=rep["filename"]
    )

# -------------------------------------------------------------
# AI ADVISOR ENDPOINTS
# -------------------------------------------------------------
@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    data = request.get_json() or {}
    connection_id = data.get("connection_id", "").strip()
    user_message = (data.get("message") or "").strip()
    chat_history = data.get("history", [])

    if not user_message:
        return jsonify({"detail": "Message cannot be empty."}), 400

    conn = None
    with STORE_LOCK:
        if connection_id and connection_id in CONNECTIONS:
            conn = CONNECTIONS[connection_id]
        elif CONNECTIONS:
            conn = list(CONNECTIONS.values())[-1]

    from app.services.ai_advisor import AIAdvisorService
    res = run_async(AIAdvisorService.process_chat(
        user_message=user_message,
        connection_data=conn,
        chat_history=chat_history
    ))
    return jsonify(res)

# -------------------------------------------------------------
# SCHEDULER & EMAIL DISPATCH ENDPOINTS
# -------------------------------------------------------------
from app.services.scheduler_service import SchedulerService, execute_scheduled_assessment

@app.route("/api/scheduler/config", methods=["GET"])
def get_scheduler_config():
    return jsonify(SchedulerService.get_email_config(mask_password=True))

@app.route("/api/scheduler/config", methods=["POST"])
def save_scheduler_config():
    data = request.get_json() or {}
    updated = SchedulerService.save_email_config(data)
    return jsonify({"status": "Saved", "config": updated})

@app.route("/api/scheduler/test-email", methods=["POST"])
def test_scheduler_email():
    data = request.get_json() or {}
    sender = data.get("sender_email", "")
    pwd = data.get("sender_password", "")
    host = data.get("smtp_host", "smtp.gmail.com")
    port = data.get("smtp_port", 587)
    use_tls = data.get("use_tls", True)
    receiver = data.get("receiver_email", "")
    cc = data.get("cc_email", "")

    res = SchedulerService.test_email_connection(
        sender=sender,
        password=pwd,
        host=host,
        port=port,
        use_tls=use_tls,
        receiver=receiver,
        cc=cc
    )
    status_code = 200 if res.get("success") else 400
    return jsonify(res), status_code

@app.route("/api/scheduler/schedules", methods=["GET"])
def list_schedules():
    return jsonify({"schedules": SchedulerService.list_schedules()})

@app.route("/api/scheduler/schedules", methods=["POST"])
def create_schedule():
    data = request.get_json() or {}
    if not data.get("name"):
        return jsonify({"detail": "Schedule name is required."}), 400
    new_sched = SchedulerService.create_schedule(data)
    return jsonify({"status": "Created", "schedule": new_sched}), 201

@app.route("/api/scheduler/schedules/<schedule_id>", methods=["DELETE"])
def delete_schedule(schedule_id):
    deleted = SchedulerService.delete_schedule(schedule_id)
    if not deleted:
        return jsonify({"detail": "Schedule not found."}), 404
    return jsonify({"status": "Deleted", "schedule_id": schedule_id})

@app.route("/api/scheduler/schedules/<schedule_id>/toggle", methods=["POST"])
def toggle_schedule(schedule_id):
    sched = SchedulerService.toggle_schedule(schedule_id)
    if not sched:
        return jsonify({"detail": "Schedule not found."}), 404
    return jsonify({"status": "Updated", "schedule": sched})

@app.route("/api/scheduler/schedules/<schedule_id>/run-now", methods=["POST"])
def run_schedule_now(schedule_id):
    schedules = SchedulerService.list_schedules()
    target_sched = next((s for s in schedules if s.get("id") == schedule_id), None)
    if not target_sched:
        return jsonify({"detail": "Schedule not found."}), 404

    # Get active connection
    with STORE_LOCK:
        if not CONNECTIONS:
            return jsonify({"detail": "No active Azure connection found. Please connect to Azure first."}), 400
        conn = list(CONNECTIONS.values())[-1]

    try:
        scope = target_sched.get("scope", "all")
        summary, results = execute_scheduled_assessment(conn, scope)

        email_res = SchedulerService.send_report_email(
            summary=summary,
            results=results,
            workspace_name=conn.get("workspace_name", "Azure Workspace"),
            scope=scope,
            schedule_name=target_sched.get("name", "Scheduled Assessment"),
            recipients_override=target_sched.get("recipients", ""),
            cc_override=target_sched.get("cc", "")
        )

        all_data = SchedulerService.load_data()
        for s in all_data.get("schedules", []):
            if s.get("id") == schedule_id:
                s["last_run_at"] = datetime.datetime.now().isoformat()
                if email_res.get("success"):
                    s["last_run_status"] = "Success"
                    s["last_run_message"] = f"Delivered to {', '.join(email_res.get('recipients', []))}"
                else:
                    s["last_run_status"] = "Email Delivery Failed"
                    s["last_run_message"] = email_res.get("detail", "Error sending email")
        SchedulerService.save_data(all_data)

        return jsonify({
            "status": "Completed",
            "email_status": email_res,
            "total_findings": summary.get("total_findings", 0),
            "annual_savings": summary.get("total_annual_savings", 0.0)
        })
    except Exception as ex:
        return jsonify({"detail": f"Execution error: {str(ex)}"}), 500

# Start background scheduler daemon
def _get_active_conn_for_scheduler():
    with STORE_LOCK:
        if CONNECTIONS:
            return list(CONNECTIONS.values())[-1]
    return None

SchedulerService.start_background_worker(_get_active_conn_for_scheduler)

if __name__ == "__main__":
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("APP_PORT", "8000")))
    print("=" * 60)
    print("AZURE FINSECOPS PLATFORM")
    print("Running unified Flask application with native HTML/JS/CSS UI")
    print(f"Access application at: http://{host}:{port}")
    print("=" * 60)
    app.run(host=host, port=port, debug=False, threaded=True)
