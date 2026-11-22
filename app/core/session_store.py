import asyncio
import datetime
import threading
import uuid
from typing import Dict, Any, Optional, List
from app.core.config import settings
from app.schemas.job import JobStatus, JobProgressModel, LogEvent
from app.schemas.subscription import SubscriptionModel

class ThreadSafeAsyncLock:
    def __init__(self):
        self._lock = threading.RLock()

    async def __aenter__(self):
        self._lock.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()

class SessionStore:
    def __init__(self):
        self._connections: Dict[str, Dict[str, Any]] = {}
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._lock = ThreadSafeAsyncLock()

    async def create_connection(
        self,
        workspace_name: str,
        tenant_id: str,
        client_id: str,
        client_secret: Optional[str] = None,
        subscriptions: Optional[List[SubscriptionModel]] = None,
        currency: str = "USD",
        target_tags: Optional[List[str]] = None,
        prod_tags: Optional[List[str]] = None,
        test_tags: Optional[List[str]] = None
    ) -> str:
        async with self._lock:
            conn_id = str(uuid.uuid4())
            now = datetime.datetime.now(datetime.timezone.utc)
            self._connections[conn_id] = {
                "connection_id": conn_id,
                "workspace_name": workspace_name,
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret, # kept only in-memory, never exported
                "subscriptions": subscriptions or [],
                "currency": currency,
                "target_tags": target_tags or [],
                "prod_tags": prod_tags or [],
                "test_tags": test_tags or [],
                "connected_at": now.isoformat(),
                "last_active": now,
                "cumulative_results": {},
                "cumulative_summary": {},
            }
            return conn_id

    async def get_connection(self, connection_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            conn = self._connections.get(connection_id)
            if conn:
                conn["last_active"] = datetime.datetime.now(datetime.timezone.utc)
            return conn

    async def remove_connection(self, connection_id: str) -> bool:
        async with self._lock:
            if connection_id in self._connections:
                # Clear credentials explicitly
                self._connections[connection_id]["client_secret"] = None
                del self._connections[connection_id]
                # Cleanup associated jobs & reports
                jobs_to_remove = [
                    jid for jid, j in self._jobs.items()
                    if j.get("connection_id") == connection_id
                ]
                for jid in jobs_to_remove:
                    self._jobs.pop(jid, None)
                    
                reports_to_remove = [
                    rid for rid, r in self._reports.items()
                    if r.get("connection_id") == connection_id
                ]
                for rid in reports_to_remove:
                    self._reports.pop(rid, None)
                return True
            return False

    async def create_job(self, connection_id: str, scope: str, total_assessments: int) -> str:
        async with self._lock:
            job_id = str(uuid.uuid4())
            now = datetime.datetime.now(datetime.timezone.utc)
            progress = JobProgressModel(
                job_id=job_id,
                status=JobStatus.PENDING,
                scope=scope,
                total_assessments=total_assessments,
                completed_assessments=0,
                running_assessments=0,
                pending_assessments=total_assessments,
                failed_assessments=0,
                current_subscription="Initializing...",
                current_assessment=None,
                progress_percentage=0.0,
                start_time=now.isoformat(),
                duration_seconds=0.0,
                assessment_statuses={},
                recent_logs=[
                    LogEvent(
                        timestamp=now.strftime("%H:%M:%S"),
                        level="INFO",
                        message=f"Assessment job initiated for scope '{scope}' with {total_assessments} modules."
                    )
                ]
            )
            self._jobs[job_id] = {
                "job_id": job_id,
                "connection_id": connection_id,
                "scope": scope,
                "status": JobStatus.PENDING,
                "progress": progress,
                "results": {},
                "summary": {},
                "created_at": now,
                "completed_at": None,
                "task": None,
            }
            return job_id

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            return self._jobs.get(job_id)

    async def update_job_progress(
        self,
        job_id: str,
        status: Optional[JobStatus] = None,
        completed_delta: int = 0,
        running_assessments: Optional[int] = None,
        failed_delta: int = 0,
        current_sub: Optional[str] = None,
        current_assessment: Optional[str] = None,
        assessment_status_update: Optional[Dict[str, Any]] = None,
        log_event: Optional[LogEvent] = None
    ):
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            prog = job["progress"]
            if status:
                job["status"] = status
                prog.status = status
            if completed_delta:
                prog.completed_assessments += completed_delta
            if running_assessments is not None:
                prog.running_assessments = running_assessments
            if failed_delta:
                prog.failed_assessments += failed_delta
            prog.pending_assessments = max(0, prog.total_assessments - prog.completed_assessments - prog.failed_assessments)
            
            if current_sub is not None:
                prog.current_subscription = current_sub
            if current_assessment is not None:
                prog.current_assessment = current_assessment
            if assessment_status_update:
                prog.assessment_statuses.update(assessment_status_update)
            if log_event:
                prog.recent_logs.append(log_event)
                # Keep last 50 logs in memory
                if len(prog.recent_logs) > 50:
                    prog.recent_logs = prog.recent_logs[-50:]
                    
            if prog.total_assessments > 0:
                prog.progress_percentage = round(
                    ((prog.completed_assessments + prog.failed_assessments) / prog.total_assessments) * 100, 1
                )
                
            start_dt = datetime.datetime.fromisoformat(prog.start_time)
            now = datetime.datetime.now(datetime.timezone.utc)
            prog.duration_seconds = round((now - start_dt).total_seconds(), 1)

    async def update_cumulative_results(self, connection_id: str, new_results: Dict[str, Any], summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        async with self._lock:
            conn = self._connections.get(connection_id)
            if not conn:
                return dict(new_results)
            cum = conn.setdefault("cumulative_results", {})
            cum.update(new_results)
            if summary:
                conn["cumulative_summary"] = summary
            return dict(cum)

    async def set_job_results(self, job_id: str, results: Dict[str, Any], summary: Dict[str, Any]):
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job["results"] = results
                job["summary"] = summary
                job["completed_at"] = datetime.datetime.now(datetime.timezone.utc)

    async def store_report(
        self,
        connection_id: str,
        report_type: str,
        filename: str,
        file_bytes: bytes,
        content_type: str
    ) -> str:
        async with self._lock:
            report_id = str(uuid.uuid4())
            now = datetime.datetime.now(datetime.timezone.utc)
            expires = now + datetime.timedelta(minutes=settings.report_ttl_minutes)
            self._reports[report_id] = {
                "report_id": report_id,
                "connection_id": connection_id,
                "report_type": report_type,
                "filename": filename,
                "bytes": file_bytes,
                "size": len(file_bytes),
                "content_type": content_type,
                "created_at": now.isoformat(),
                "expires_at": expires.isoformat(),
                "expires_dt": expires,
            }
            return report_id

    async def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            return self._reports.get(report_id)

    async def cleanup_expired(self):
        async with self._lock:
            now = datetime.datetime.now(datetime.timezone.utc)
            # Cleanup reports
            expired_reports = [
                rid for rid, r in self._reports.items()
                if r.get("expires_dt") and r["expires_dt"] < now
            ]
            for rid in expired_reports:
                del self._reports[rid]

            # Cleanup expired jobs
            job_ttl = datetime.timedelta(minutes=settings.job_ttl_minutes)
            expired_jobs = [
                jid for jid, j in self._jobs.items()
                if j.get("created_at") and (now - j["created_at"]) > job_ttl
            ]
            for jid in expired_jobs:
                del self._jobs[jid]

session_store = SessionStore()
