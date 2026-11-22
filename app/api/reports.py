import datetime
from fastapi import APIRouter, HTTPException, Response
from typing import Optional, Dict, Any
from app.core.session_store import session_store
from app.reports.pdf.security_pdf import generate_security_pdf
from app.reports.pdf.cost_pdf import generate_cost_pdf
from app.reports.pdf.combined_pdf import generate_combined_pdf
from app.reports.excel.security_excel import generate_security_excel
from app.reports.excel.cost_excel import generate_cost_excel
from app.reports.excel.combined_excel import generate_combined_excel
from app.reports.pdf.single_pdf import generate_single_pdf
from app.reports.excel.single_excel import generate_single_excel
from app.assessments.registry import assessment_registry

router = APIRouter(prefix="/api/reports", tags=["Reports"])

async def _prepare_report_payload(job_id: str, client_payload: Optional[Dict[str, Any]] = None):
    """
    Assembles complete cumulative assessment results across the entire connection session.
    Ensures that running security then cost, or individual modules, preserves all data in deliverables.
    Returns: (report_data, workspace_name, tenant_id, connection_id)
    """
    job = await session_store.get_job(job_id)
    conn_id = job.get("connection_id") if job else job_id
    if client_payload and isinstance(client_payload, dict) and client_payload.get("connection_id"):
        if not conn_id or conn_id == job_id:
            candidate_conn = await session_store.get_connection(client_payload.get("connection_id"))
            if candidate_conn:
                conn_id = client_payload.get("connection_id")
    conn = await session_store.get_connection(conn_id)

    if not job and not conn:
        raise HTTPException(status_code=404, detail="Assessment job or connection session not found.")

    ws_name = conn.get("workspace_name", "Workspace") if conn else "Workspace"
    tenant_id = conn.get("tenant_id", "") if conn else ""
    currency = conn.get("currency", "USD") if conn else "USD"

    # 1. Accumulate all session results across all runs in this session
    all_results = {}
    if conn and conn.get("cumulative_results"):
        all_results.update(conn["cumulative_results"])
    if job and job.get("results"):
        for k, v in job["results"].items():
            if k not in all_results or (isinstance(v, dict) and v.get("findings_count", 0) > 0) or getattr(v, "findings_count", 0) > 0:
                all_results[k] = v
    if client_payload and isinstance(client_payload, dict) and client_payload.get("results"):
        for k, v in client_payload["results"].items():
            if k not in all_results or (isinstance(v, dict) and v.get("findings_count", 0) > 0):
                all_results[k] = v

    if conn:
        conn["cumulative_results"] = all_results

    # 2. Compute authoritative cumulative summary across all accumulated results
    from app.intelligence.aggregation import AssessmentAggregator
    report_summary = AssessmentAggregator.aggregate_results(all_results, default_currency=currency)

    subs_list = (conn.get("subscriptions", []) if conn else []) or (job.get("subscriptions", []) if job else [])
    if not subs_list and client_payload and isinstance(client_payload, dict) and client_payload.get("subscriptions"):
        subs_list = client_payload.get("subscriptions", [])

    report_summary["subscriptions_count"] = len(subs_list) if subs_list else 1

    report_data = {
        "job_id": job.get("job_id", job_id) if job else job_id,
        "scope": "all",
        "results": all_results,
        "summary": report_summary,
        "subscriptions": subs_list,
        "created_at": (job.get("created_at") if job else None) or datetime.datetime.now(datetime.timezone.utc)
    }

    return report_data, ws_name, tenant_id, conn_id

@router.post("/security/pdf/{job_id}")
async def create_security_pdf(job_id: str, payload: Optional[Dict[str, Any]] = None):
    report_data, ws_name, tenant_id, conn_id = await _prepare_report_payload(job_id, payload)
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{ws_name.replace(' ', '_')}_Security_Assessment_{date_str}.pdf"

    pdf_bytes = generate_security_pdf(report_data, ws_name, tenant_id)
    report_id = await session_store.store_report(
        connection_id=conn_id,
        report_type="security_pdf",
        filename=filename,
        file_bytes=pdf_bytes,
        content_type="application/pdf"
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.post("/security/excel/{job_id}")
async def create_security_excel(job_id: str, payload: Optional[Dict[str, Any]] = None):
    report_data, ws_name, tenant_id, conn_id = await _prepare_report_payload(job_id, payload)
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{ws_name.replace(' ', '_')}_Security_Assessment_{date_str}.xlsx"

    xlsx_bytes = generate_security_excel(report_data, ws_name, tenant_id)
    report_id = await session_store.store_report(
        connection_id=conn_id,
        report_type="security_excel",
        filename=filename,
        file_bytes=xlsx_bytes,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.post("/cost/pdf/{job_id}")
async def create_cost_pdf(job_id: str, payload: Optional[Dict[str, Any]] = None):
    report_data, ws_name, tenant_id, conn_id = await _prepare_report_payload(job_id, payload)
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{ws_name.replace(' ', '_')}_Cost_Optimization_{date_str}.pdf"

    pdf_bytes = generate_cost_pdf(report_data, ws_name, tenant_id)
    report_id = await session_store.store_report(
        connection_id=conn_id,
        report_type="cost_pdf",
        filename=filename,
        file_bytes=pdf_bytes,
        content_type="application/pdf"
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.post("/cost/excel/{job_id}")
async def create_cost_excel(job_id: str, payload: Optional[Dict[str, Any]] = None):
    report_data, ws_name, tenant_id, conn_id = await _prepare_report_payload(job_id, payload)
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{ws_name.replace(' ', '_')}_Cost_Optimization_{date_str}.xlsx"

    xlsx_bytes = generate_cost_excel(report_data, ws_name, tenant_id)
    report_id = await session_store.store_report(
        connection_id=conn_id,
        report_type="cost_excel",
        filename=filename,
        file_bytes=xlsx_bytes,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.post("/combined/pdf/{job_id}")
async def create_combined_pdf(job_id: str, payload: Optional[Dict[str, Any]] = None):
    report_data, ws_name, tenant_id, conn_id = await _prepare_report_payload(job_id, payload)
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{ws_name.replace(' ', '_')}_Comprehensive_Assessment_{date_str}.pdf"

    pdf_bytes = generate_combined_pdf(report_data, ws_name, tenant_id)
    report_id = await session_store.store_report(
        connection_id=conn_id,
        report_type="combined_pdf",
        filename=filename,
        file_bytes=pdf_bytes,
        content_type="application/pdf"
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.post("/combined/excel/{job_id}")
async def create_combined_excel(job_id: str, payload: Optional[Dict[str, Any]] = None):
    report_data, ws_name, tenant_id, conn_id = await _prepare_report_payload(job_id, payload)
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"{ws_name.replace(' ', '_')}_Comprehensive_Assessment_{date_str}.xlsx"

    xlsx_bytes = generate_combined_excel(report_data, ws_name, tenant_id)
    report_id = await session_store.store_report(
        connection_id=conn_id,
        report_type="combined_excel",
        filename=filename,
        file_bytes=xlsx_bytes,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.post("/single/{format}/{assessment_id}")
async def create_single_report(format: str, assessment_id: str, payload: Optional[Dict[str, Any]] = None):
    """
    Generates an individual module PDF or Excel report containing the exact findings for that specific assessment card.
    """
    ass_def = assessment_registry.get_assessment(assessment_id)
    if not ass_def:
        raise HTTPException(status_code=404, detail=f"Assessment module '{assessment_id}' not found.")

    conn_id = payload.get("connection_id") if payload else None
    conn = await session_store.get_connection(conn_id) if conn_id else None
    ws_name = conn.get("workspace_name", "Workspace") if conn else "Workspace"
    tenant_id = conn.get("tenant_id", "") if conn else ""

    # Fetch assessment findings from payload or cumulative results
    res_data = {}
    if payload and isinstance(payload, dict) and payload.get("results"):
        res_data = payload["results"].get(assessment_id, {})
    if not res_data and conn and conn.get("cumulative_results"):
        res_data = conn["cumulative_results"].get(assessment_id, {})

    code = getattr(ass_def, "code", "ASS")
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    safe_name = ass_def.name.replace(" ", "_").replace("/", "-")

    if format.lower() == "pdf":
        filename = f"{ws_name.replace(' ', '_')}_{code}_{safe_name}_{date_str}.pdf"
        file_bytes = generate_single_pdf(ass_def, res_data, ws_name, tenant_id)
        content_type = "application/pdf"
    elif format.lower() == "excel":
        filename = f"{ws_name.replace(' ', '_')}_{code}_{safe_name}_{date_str}.xlsx"
        file_bytes = generate_single_excel(ass_def, res_data, ws_name, tenant_id)
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'. Use 'pdf' or 'excel'.")

    report_id = await session_store.store_report(
        connection_id=conn_id or "global",
        report_type=f"single_{format.lower()}",
        filename=filename,
        file_bytes=file_bytes,
        content_type=content_type
    )

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}"
    }

@router.get("/download/{report_id}")
async def download_report(report_id: str):
    report = await session_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report artifact not found or expired.")

    return Response(
        content=report["bytes"],
        media_type=report["content_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{report["filename"]}"'
        }
    )

@router.delete("/{report_id}")
async def delete_report(report_id: str):
    return {"success": True, "message": "Report deleted."}
