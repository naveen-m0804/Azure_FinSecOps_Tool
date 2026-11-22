import asyncio
import datetime
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.assessments.registry import assessment_registry
from app.core.session_store import session_store
from app.core.azure_client_factory import azure_client_factory
from app.schemas.job import JobStatus, LogEvent
from app.schemas.assessment import AssessmentStatus, AssessmentResult
from app.intelligence.aggregation import AssessmentAggregator
from app.core.config import settings

class AssessmentJobRunner:
    @staticmethod
    async def start_job(
        connection_id: str,
        scope: str = "all",
        single_assessment_id: Optional[str] = None
    ) -> str:
        conn = await session_store.get_connection(connection_id)
        if not conn:
            raise ValueError(f"Active connection '{connection_id}' not found.")

        # Determine target assessments
        if single_assessment_id:
            ass_instance = assessment_registry.get_assessment(single_assessment_id)
            if not ass_instance:
                raise ValueError(f"Assessment '{single_assessment_id}' not registered.")
            target_assessments = [ass_instance]
        elif scope == "security":
            target_assessments = assessment_registry.get_security_assessments()
        elif scope == "cost":
            target_assessments = assessment_registry.get_cost_assessments()
        else:
            target_assessments = assessment_registry.get_all_assessments()

        job_id = await session_store.create_job(
            connection_id=connection_id,
            scope=scope if not single_assessment_id else single_assessment_id,
            total_assessments=len(target_assessments)
        )

        # Launch background execution task
        asyncio.create_task(
            AssessmentJobRunner._execute_job(
                job_id=job_id,
                connection=conn,
                assessments=target_assessments
            )
        )

        return job_id

    @staticmethod
    async def _execute_job(
        job_id: str,
        connection: Dict[str, Any],
        assessments: List[BaseAssessment]
    ):
        await session_store.update_job_progress(
            job_id=job_id,
            status=JobStatus.RUNNING,
            current_sub="Initializing subscriptions...",
            log_event=LogEvent(
                timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
                level="INFO",
                message=f"Starting scan across {len(connection.get('subscriptions', []))} subscription(s)."
            )
        )

        client = None
        try:
            client = await azure_client_factory.get_client_for_session(
                tenant_id=connection["tenant_id"],
                client_id=connection["client_id"],
                client_secret=connection.get("client_secret")
            )
        except Exception as ex:
            await session_store.update_job_progress(
                job_id=job_id,
                status=JobStatus.FAILED,
                log_event=LogEvent(
                    timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
                    level="ERROR",
                    message=f"Failed to initialize Azure ARM client: {str(ex)}"
                )
            )
            return

        context = AssessmentContext(
            connection_id=connection["connection_id"],
            workspace_name=connection["workspace_name"],
            tenant_id=connection["tenant_id"],
            subscriptions=connection.get("subscriptions", []),
            client=client,
            currency=connection.get("currency", "USD"),
            target_tags=connection.get("target_tags", []),
            prod_tags=connection.get("prod_tags", []),
            test_tags=connection.get("test_tags", []),
            client_id=connection.get("client_id"),
            client_secret=connection.get("client_secret")
        )

        results: Dict[str, AssessmentResult] = {}
        sem = asyncio.Semaphore(settings.max_concurrent_assessments)

        async def run_single(assessment: BaseAssessment):
            async with sem:
                now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
                await session_store.update_job_progress(
                    job_id=job_id,
                    current_assessment=assessment.name,
                    assessment_status_update={assessment.assessment_id: AssessmentStatus.RUNNING},
                    log_event=LogEvent(
                        timestamp=now_str,
                        level="INFO",
                        assessment_id=assessment.assessment_id,
                        message=f"Evaluating module [{assessment.code}] {assessment.name}..."
                    )
                )

                try:
                    res = await assessment.run(context)
                    
                    # Ensure all findings have clean, accurate human-readable names and no raw IDs
                    sub_name_map = {s.subscription_id: s.display_name for s in context.subscriptions if s.display_name}
                    for f in res.findings:
                        if f.subscription_id and f.subscription_id in sub_name_map:
                            f.subscription_name = sub_name_map[f.subscription_id]
                        elif f.subscription_name and f.subscription_name in sub_name_map:
                            f.subscription_name = sub_name_map[f.subscription_name]

                    # Accumulate cost findings in context for cross-module opportunity ranking
                    if res.category == "cost" and res.findings:
                        context.cached_cost_findings.extend(res.findings)

                    # Ensure security_score_improvement is always populated if findings have security_score_impact
                    if res.category == "security" and (res.security_score_improvement is None or res.security_score_improvement <= 0) and res.findings:
                        total_impact = sum(float(f.security_score_impact or 0.0) for f in res.findings)
                        if total_impact > 0:
                            res.security_score_improvement = round(total_impact, 1)

                    results[assessment.assessment_id] = res

                    if res.status == AssessmentStatus.NOT_SUPPORTED:
                        log_lvl = "INFO"
                        msg = f"[{assessment.code}] Not Supported: {res.errors[0] if res.errors else 'Feature or plan not enabled on subscription.'}"
                    elif res.status == AssessmentStatus.METRICS_UNAVAILABLE:
                        log_lvl = "WARNING"
                        msg = f"[{assessment.code}] Metrics Unavailable: {res.findings_count} resource(s) missing monitoring telemetry."
                    elif res.status == AssessmentStatus.PERMISSION_MISSING:
                        log_lvl = "WARNING"
                        msg = f"[{assessment.code}] Permission Missing: {res.errors[0] if res.errors else 'Required Azure RBAC action missing.'}"
                    elif res.findings_count > 0:
                        log_lvl = "SUCCESS"
                        msg = f"[{assessment.code}] Completed with {res.findings_count} finding(s)."
                    else:
                        log_lvl = "INFO"
                        msg = f"[{assessment.code}] Completed: No compliance or optimization issues detected."

                    await session_store.update_job_progress(
                        job_id=job_id,
                        completed_delta=1,
                        assessment_status_update={assessment.assessment_id: res.status},
                        log_event=LogEvent(
                            timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
                            level=log_lvl,
                            assessment_id=assessment.assessment_id,
                            message=msg
                        )
                    )
                except Exception as ex:
                    res = assessment.create_empty_result(AssessmentStatus.FAILED)
                    res.errors.append(str(ex))
                    results[assessment.assessment_id] = res

                    await session_store.update_job_progress(
                        job_id=job_id,
                        failed_delta=1,
                        assessment_status_update={assessment.assessment_id: AssessmentStatus.FAILED},
                        log_event=LogEvent(
                            timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
                            level="ERROR",
                            assessment_id=assessment.assessment_id,
                            message=f"[{assessment.code}] Assessment failed: {str(ex)}"
                        )
                    )

        tasks = [run_single(a) for a in assessments]
        await asyncio.gather(*tasks)

        # Merge and persist cumulative results across all runs in this session
        merged_results = await session_store.update_cumulative_results(
            connection_id=connection["connection_id"],
            new_results=results
        )

        # Aggregate final findings and summary across cumulative results
        summary = AssessmentAggregator.aggregate_results(merged_results, default_currency=context.currency)
        await session_store.update_cumulative_results(
            connection_id=connection["connection_id"],
            new_results={},
            summary=summary
        )

        final_status = JobStatus.COMPLETED
        if summary["failed_modules"] > 0:
            final_status = (
                JobStatus.FAILED if summary["failed_modules"] == len(merged_results) else JobStatus.COMPLETED_WITH_WARNINGS
            )

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        await session_store.set_job_results(job_id, merged_results, summary)
        await session_store.update_job_progress(
            job_id=job_id,
            status=final_status,
            current_assessment="All assessments finished",
            current_sub="Completed",
            log_event=LogEvent(
                timestamp=now_str,
                level="SUCCESS",
                message=f"Scan finished. {summary['total_findings']} total finding(s) identified across {len(assessments)} modules."
            )
        )
