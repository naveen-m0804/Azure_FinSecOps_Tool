import os
import json
import uuid
import smtplib
import logging
import datetime
import threading
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, List, Optional

logger = logging.getLogger("azure_finsecops.scheduler")

DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "scheduler_config.json")

class SchedulerService:
    _lock = threading.Lock()
    _worker_started = False

    @classmethod
    def _ensure_data_dir(cls):
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

    @classmethod
    def load_data(cls) -> Dict[str, Any]:
        """Loads persisted email configuration and schedules from disk."""
        with cls._lock:
            if not os.path.exists(DATA_FILE):
                return {
                    "email_config": {
                        "smtp_host": "smtp.gmail.com",
                        "smtp_port": 587,
                        "use_tls": True,
                        "sender_email": "",
                        "sender_password": "",
                        "default_receiver": "",
                        "default_cc": ""
                    },
                    "schedules": []
                }
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    data.setdefault("email_config", {
                        "smtp_host": "smtp.gmail.com",
                        "smtp_port": 587,
                        "use_tls": True,
                        "sender_email": "",
                        "sender_password": "",
                        "default_receiver": "",
                        "default_cc": ""
                    })
                    data.setdefault("schedules", [])
                    return data
            except Exception as e:
                logger.error(f"Failed to read scheduler config: {e}")
                return {"email_config": {}, "schedules": []}

    @classmethod
    def save_data(cls, data: Dict[str, Any]):
        """Persists email configuration and schedules to disk."""
        with cls._lock:
            cls._ensure_data_dir()
            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
            except Exception as e:
                logger.error(f"Failed to write scheduler config: {e}")

    @classmethod
    def get_email_config(cls, mask_password: bool = True) -> Dict[str, Any]:
        data = cls.load_data()
        cfg = dict(data.get("email_config", {}))
        if mask_password and cfg.get("sender_password"):
            cfg["sender_password_masked"] = "••••••••••••"
            cfg["has_password"] = True
            del cfg["sender_password"]
        else:
            cfg["has_password"] = bool(cfg.get("sender_password"))
        return cfg

    @classmethod
    def save_email_config(cls, new_cfg: Dict[str, Any]) -> Dict[str, Any]:
        data = cls.load_data()
        current_cfg = data.get("email_config", {})

        # If password is omitted or masked in input, retain existing password
        pwd = new_cfg.get("sender_password", "")
        if not pwd or pwd == "••••••••••••":
            new_cfg["sender_password"] = current_cfg.get("sender_password", "")

        try:
            port = int(new_cfg.get("smtp_port", 587))
        except (ValueError, TypeError):
            port = 587

        updated = {
            "smtp_host": str(new_cfg.get("smtp_host", "smtp.gmail.com")).strip(),
            "smtp_port": port,
            "use_tls": bool(new_cfg.get("use_tls", True)),
            "sender_email": str(new_cfg.get("sender_email", "")).strip(),
            "sender_password": str(new_cfg.get("sender_password", "")),
            "default_receiver": str(new_cfg.get("default_receiver", "")).strip(),
            "default_cc": str(new_cfg.get("default_cc", "")).strip()
        }

        data["email_config"] = updated
        cls.save_data(data)
        return cls.get_email_config(mask_password=True)

    @classmethod
    def test_email_connection(
        cls,
        sender: str,
        password: str,
        host: str = "smtp.gmail.com",
        port: int = 587,
        use_tls: bool = True,
        receiver: str = "",
        cc: str = ""
    ) -> Dict[str, Any]:
        """Validates SMTP credentials by sending an actual verification email."""
        sender = sender.strip()
        receiver = receiver.strip()
        if not sender:
            return {"success": False, "detail": "Sender email address is required."}
        if not password:
            # Check if there is an existing password saved
            saved = cls.load_data().get("email_config", {})
            password = saved.get("sender_password", "")
            if not password:
                return {"success": False, "detail": "Sender app password is required."}

        if not receiver:
            receiver = sender  # Test to self if no receiver specified

        host = (host or "smtp.gmail.com").strip()
        try:
            port = int(port or 587)
        except ValueError:
            port = 587

        # Parse recipients
        to_list = [r.strip() for r in receiver.split(",") if r.strip()]
        cc_list = [c.strip() for c in cc.split(",") if c.strip()] if cc else []
        all_recipients = list(set(to_list + cc_list))

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "✅ [Azure FinSecOps] SMTP Configuration Verification"
        msg["From"] = sender
        msg["To"] = ", ".join(to_list)
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 24px; color: #1e293b; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }}
            .header {{ background: linear-gradient(135deg, #1e3a8a, #4338ca); color: #ffffff; padding: 28px; text-align: center; }}
            .header h1 {{ margin: 0 0 6px 0; font-size: 22px; font-weight: 700; }}
            .header p {{ margin: 0; font-size: 13px; opacity: 0.9; }}
            .content {{ padding: 28px; }}
            .badge-success {{ display: inline-block; background-color: #dcfce7; color: #166534; padding: 6px 14px; border-radius: 20px; font-weight: 600; font-size: 13px; margin-bottom: 16px; }}
            .info-table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
            .info-table td {{ padding: 10px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }}
            .info-table td.label {{ color: #64748b; font-weight: 600; width: 40%; }}
            .info-table td.value {{ color: #0f172a; font-family: monospace; }}
            .footer {{ background: #f8fafc; padding: 16px 28px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Azure FinSecOps Platform</h1>
              <p>Email Dispatch & Automated Scheduler Service</p>
            </div>
            <div class="content">
              <span class="badge-success">✓ SMTP Authentication Verified</span>
              <p>Your SMTP mail credentials have been successfully authenticated with <strong>{host}:{port}</strong>.</p>
              <p>The Azure FinSecOps automated scheduler will use these settings to dispatch executive security and FinOps optimization reports directly to your configured recipients.</p>
              
              <table class="info-table">
                <tr><td class="label">SMTP Server:</td><td class="value">{host}:{port}</td></tr>
                <tr><td class="label">TLS Encryption:</td><td class="value">{'Enabled (STARTTLS)' if use_tls else 'None / SSL'}</td></tr>
                <tr><td class="label">Sender Address:</td><td class="value">{sender}</td></tr>
                <tr><td class="label">Primary Recipient:</td><td class="value">{', '.join(to_list)}</td></tr>
                {f'<tr><td class="label">CC Recipients:</td><td class="value">{", ".join(cc_list)}</td></tr>' if cc_list else ''}
                <tr><td class="label">Verified At:</td><td class="value">{now_str}</td></tr>
              </table>
            </div>
            <div class="footer">
              This is an automated verification email sent by your Azure Cloud Governance Platform.
            </div>
          </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, "html"))

        try:
            if port == 465:
                server = smtplib.SMTP_SSL(host, port, timeout=12)
            else:
                server = smtplib.SMTP(host, port, timeout=12)

            server.ehlo()
            if use_tls and port != 465:
                server.starttls()
                server.ehlo()

            server.login(sender, password)
            server.sendmail(sender, all_recipients, msg.as_string())
            server.quit()

            return {
                "success": True,
                "detail": f"Verification email sent successfully to {', '.join(all_recipients)} via {host}:{port}."
            }
        except smtplib.SMTPAuthenticationError as auth_err:
            hint = ""
            if "gmail" in host.lower():
                hint = " For Gmail, you must use a 16-character 'App Password' generated at myaccount.google.com/apppasswords, not your standard login password."
            return {"success": False, "detail": f"SMTP Authentication Failed: {auth_err.smtp_error.decode('utf-8', errors='ignore') if isinstance(auth_err.smtp_error, bytes) else str(auth_err)}.{hint}"}
        except Exception as e:
            return {"success": False, "detail": f"SMTP Connection Error: {str(e)}"}

    @classmethod
    def list_schedules(cls) -> List[Dict[str, Any]]:
        data = cls.load_data()
        return data.get("schedules", [])

    @classmethod
    def create_schedule(cls, sched_data: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a new scheduled assessment job."""
        data = cls.load_data()
        email_cfg = data.get("email_config", {})

        name = str(sched_data.get("name") or "Scheduled Assessment").strip()
        scope = str(sched_data.get("scope") or "all").lower()
        if scope not in ["all", "security", "cost"]:
            scope = "all"

        frequency = str(sched_data.get("frequency") or "daily").lower()
        time_of_day = str(sched_data.get("time_of_day") or "09:00").strip()
        day_of_week = str(sched_data.get("day_of_week") or "Monday").strip()
        day_of_month = int(sched_data.get("day_of_month") or 1)

        recipients = str(sched_data.get("recipients") or email_cfg.get("default_receiver") or "").strip()
        cc = str(sched_data.get("cc") or email_cfg.get("default_cc") or "").strip()

        next_run = cls._calculate_next_run(frequency, time_of_day, day_of_week, day_of_month)

        new_item = {
            "id": str(uuid.uuid4()),
            "name": name,
            "scope": scope,
            "frequency": frequency,
            "time_of_day": time_of_day,
            "day_of_week": day_of_week,
            "day_of_month": day_of_month,
            "recipients": recipients,
            "cc": cc,
            "include_body_report": bool(sched_data.get("include_body_report", True)),
            "status": "Active",
            "created_at": datetime.datetime.now().isoformat(),
            "last_run_at": None,
            "last_run_status": "Pending Initial Run",
            "last_run_message": "",
            "next_run_at": next_run.isoformat()
        }

        data.setdefault("schedules", []).append(new_item)
        cls.save_data(data)
        return new_item

    @classmethod
    def delete_schedule(cls, schedule_id: str) -> bool:
        data = cls.load_data()
        schedules = data.get("schedules", [])
        initial_len = len(schedules)
        data["schedules"] = [s for s in schedules if s.get("id") != schedule_id]
        if len(data["schedules"]) < initial_len:
            cls.save_data(data)
            return True
        return False

    @classmethod
    def toggle_schedule(cls, schedule_id: str) -> Optional[Dict[str, Any]]:
        data = cls.load_data()
        for s in data.get("schedules", []):
            if s.get("id") == schedule_id:
                s["status"] = "Paused" if s.get("status") == "Active" else "Active"
                cls.save_data(data)
                return s
        return None

    @classmethod
    def _calculate_next_run(cls, frequency: str, time_of_day: str, day_of_week: str, day_of_month: int) -> datetime.datetime:
        now = datetime.datetime.now()
        try:
            hour, minute = map(int, time_of_day.split(":"))
        except Exception:
            hour, minute = 9, 0

        target_today = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if frequency == "hourly":
            nxt = now + datetime.timedelta(hours=1)
            return nxt.replace(minute=minute, second=0, microsecond=0)

        if frequency == "every_6_hours":
            nxt = now + datetime.timedelta(hours=6)
            return nxt.replace(second=0, microsecond=0)

        if frequency == "daily":
            if target_today > now:
                return target_today
            return target_today + datetime.timedelta(days=1)

        if frequency == "weekly":
            weekday_map = {
                "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
                "friday": 4, "saturday": 5, "sunday": 6
            }
            target_weekday = weekday_map.get(day_of_week.lower(), 0)
            days_ahead = (target_weekday - now.weekday()) % 7
            if days_ahead == 0 and target_today <= now:
                days_ahead = 7
            target_date = target_today + datetime.timedelta(days=days_ahead)
            return target_date

        if frequency == "monthly":
            # Next month on day_of_month
            month = now.month
            year = now.year
            if target_today.day == day_of_month and target_today > now:
                return target_today

            if month == 12:
                year += 1
                month = 1
            else:
                month += 1
            # Adjust if day exceeds days in target month
            safe_day = min(day_of_month, 28)
            return datetime.datetime(year, month, safe_day, hour, minute)

        # Fallback daily
        return target_today if target_today > now else target_today + datetime.timedelta(days=1)

    @classmethod
    def generate_html_report_email(
        cls,
        summary: Dict[str, Any],
        results: Dict[str, Any],
        workspace_name: str,
        scope: str,
        schedule_name: str
    ) -> str:
        """Generates an executive-grade HTML email body containing complete assessment results."""
        now_str = datetime.datetime.now().strftime("%B %d, %Y at %H:%M:%S UTC")
        currency = summary.get("default_currency", "USD")
        curr_symbol = "$" if currency == "USD" else currency

        sec_score = summary.get("current_security_score", 0.0)
        baseline = summary.get("baseline_security_score", 0.0)
        achievable = summary.get("achievable_security_score", 0.0)
        annual_savings = summary.get("total_annual_savings", 0.0)
        monthly_savings = summary.get("total_monthly_savings", 0.0)
        total_findings = summary.get("total_findings", 0)

        crit = summary.get("critical_findings", 0)
        high = summary.get("high_findings", 0)
        med = summary.get("medium_findings", 0)
        low = summary.get("low_findings", 0)

        scope_title = {
            "all": "Comprehensive Security & FinOps Assessment",
            "security": "Security Governance & Compliance Assessment",
            "cost": "Financial Optimization & FinOps Assessment"
        }.get(scope, "Cloud Governance Assessment")

        # Table rows for modules
        module_rows = []
        for ass_id, res in results.items():
            code = getattr(res, "code", ass_id)
            name = getattr(res, "name", ass_id)
            status = getattr(res, "status", "Completed")
            status_val = status.value if hasattr(status, "value") else str(status)
            findings_count = getattr(res, "findings_count", 0)
            savings = getattr(res, "savings_annual", 0.0)
            score_imp = getattr(res, "security_score_improvement", 0.0)

            impact_str = "--"
            if savings > 0:
                impact_str = f"<strong style='color:#16a34a;'>{curr_symbol}{savings:,.2f}/yr</strong>"
            elif score_imp > 0:
                impact_str = f"<strong style='color:#4338ca;'>+{score_imp:.1f}%</strong>"

            badge_style = "background:#f1f5f9; color:#475569;"
            if findings_count > 0:
                badge_style = "background:#fee2e2; color:#b91c1c;"

            module_rows.append(f"""
            <tr>
              <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; font-weight:600; font-size:13px;">{code}</td>
              <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; font-size:13px; color:#334155;">{name}</td>
              <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; text-align:center;">
                <span style="display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:600; {badge_style}">
                  {findings_count} findings
                </span>
              </td>
              <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; font-size:13px; text-align:right;">{impact_str}</td>
            </tr>
            """)

        modules_html = "".join(module_rows) if module_rows else "<tr><td colspan='4' style='padding:16px; text-align:center; color:#64748b;'>No assessment modules evaluated.</td></tr>"

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color:#f1f5f9; margin:0; padding:24px; color:#0f172a; }}
            .card {{ max-width: 680px; margin:0 auto; background:#ffffff; border-radius:14px; overflow:hidden; box-shadow:0 10px 25px -5px rgba(0,0,0,0.08); border:1px solid #e2e8f0; }}
            .hero {{ background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4338ca 100%); color:#ffffff; padding:32px 28px; text-align:left; }}
            .hero-badge {{ display:inline-block; background:rgba(255,255,255,0.18); color:#e0e7ff; padding:4px 12px; border-radius:16px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:12px; }}
            .hero h1 {{ margin:0 0 6px 0; font-size:22px; font-weight:700; color:#ffffff; }}
            .hero p {{ margin:0; font-size:13px; color:#c7d2fe; }}
            
            .kpi-grid {{ display:flex; flex-wrap:wrap; margin:20px; gap:12px; }}
            .kpi-card {{ flex:1 1 calc(50% - 12px); background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:16px; box-sizing:border-box; }}
            .kpi-label {{ font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:#64748b; margin-bottom:6px; }}
            .kpi-val {{ font-size:22px; font-weight:700; color:#0f172a; margin-bottom:4px; }}
            .kpi-sub {{ font-size:11px; color:#64748b; }}

            .section {{ padding:0 20px 24px 20px; }}
            .section-title {{ font-size:15px; font-weight:700; color:#1e293b; margin:16px 0 10px 0; display:flex; align-items:center; }}

            .severity-bar {{ display:flex; background:#f1f5f9; border-radius:8px; padding:12px; margin-bottom:16px; gap:8px; text-align:center; }}
            .sev-box {{ flex:1; padding:8px 4px; border-radius:6px; }}
            .sev-crit {{ background:#fee2e2; color:#991b1b; }}
            .sev-high {{ background:#ffedd5; color:#9a3412; }}
            .sev-med {{ background:#fef9c3; color:#854d0e; }}
            .sev-low {{ background:#e0f2fe; color:#075985; }}
            .sev-num {{ font-size:16px; font-weight:800; display:block; }}
            .sev-lbl {{ font-size:10px; font-weight:600; text-transform:uppercase; }}

            table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
            th {{ background:#f8fafc; color:#475569; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; padding:10px 12px; text-align:left; border-bottom:2px solid #e2e8f0; }}

            .footer {{ background:#f8fafc; padding:20px; text-align:center; font-size:11px; color:#94a3b8; border-top:1px solid #e2e8f0; }}
            .footer strong {{ color:#475569; }}
          </style>
        </head>
        <body>
          <div class="card">
            <div class="hero">
              <span class="hero-badge">Scheduled Executive Audit</span>
              <h1>{scope_title}</h1>
              <p>Workspace: <strong>{workspace_name}</strong> &bull; Schedule: <strong>{schedule_name}</strong></p>
            </div>

            <!-- KPI Summary Grid -->
            <table style="width:100%; border-collapse:collapse; padding:16px; margin:16px 0;">
              <tr>
                <td style="width:50%; padding:8px 16px;">
                  <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:16px;">
                    <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:#64748b;">Security Posture Score</div>
                    <div style="font-size:24px; font-weight:700; color:#4338ca;">{sec_score:.1f}%</div>
                    <div style="font-size:11px; color:#64748b;">Baseline: {baseline:.1f}% &bull; Achievable: <strong>{achievable:.1f}%</strong></div>
                  </div>
                </td>
                <td style="width:50%; padding:8px 16px;">
                  <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:16px;">
                    <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:#64748b;">Annual FinOps Savings</div>
                    <div style="font-size:24px; font-weight:700; color:#16a34a;">{curr_symbol}{annual_savings:,.2f}</div>
                    <div style="font-size:11px; color:#64748b;">Recurring: {curr_symbol}{monthly_savings:,.2f} / month</div>
                  </div>
                </td>
              </tr>
            </table>

            <div class="section">
              <div class="section-title">Findings by Severity</div>
              <table style="width:100%; border-collapse:collapse; text-align:center;">
                <tr>
                  <td style="width:25%; padding:4px;">
                    <div style="background:#fee2e2; border-radius:8px; padding:10px;">
                      <span style="font-size:18px; font-weight:800; color:#991b1b; display:block;">{crit}</span>
                      <span style="font-size:10px; font-weight:700; color:#991b1b; text-transform:uppercase;">Critical</span>
                    </div>
                  </td>
                  <td style="width:25%; padding:4px;">
                    <div style="background:#ffedd5; border-radius:8px; padding:10px;">
                      <span style="font-size:18px; font-weight:800; color:#9a3412; display:block;">{high}</span>
                      <span style="font-size:10px; font-weight:700; color:#9a3412; text-transform:uppercase;">High</span>
                    </div>
                  </td>
                  <td style="width:25%; padding:4px;">
                    <div style="background:#fef9c3; border-radius:8px; padding:10px;">
                      <span style="font-size:18px; font-weight:800; color:#854d0e; display:block;">{med}</span>
                      <span style="font-size:10px; font-weight:700; color:#854d0e; text-transform:uppercase;">Medium</span>
                    </div>
                  </td>
                  <td style="width:25%; padding:4px;">
                    <div style="background:#e0f2fe; border-radius:8px; padding:10px;">
                      <span style="font-size:18px; font-weight:800; color:#075985; display:block;">{low}</span>
                      <span style="font-size:10px; font-weight:700; color:#075985; text-transform:uppercase;">Low</span>
                    </div>
                  </td>
                </tr>
              </table>

              <div class="section-title" style="margin-top:24px;">Evaluated Modules Breakdown ({len(results)} Modules)</div>
              <table>
                <thead>
                  <tr>
                    <th>Code</th>
                    <th>Assessment Module</th>
                    <th style="text-align:center;">Findings</th>
                    <th style="text-align:right;">Impact</th>
                  </tr>
                </thead>
                <tbody>
                  {modules_html}
                </tbody>
              </table>
            </div>

            <div class="footer">
              <p style="margin:0 0 6px 0;">This automated deliverable was generated by <strong>Azure FinSecOps Governance Platform</strong>.</p>
              <p style="margin:0;">Dispatched on {now_str}</p>
            </div>
          </div>
        </body>
        </html>
        """

    @classmethod
    def send_report_email(
        cls,
        summary: Dict[str, Any],
        results: Dict[str, Any],
        workspace_name: str,
        scope: str,
        schedule_name: str,
        recipients_override: str = "",
        cc_override: str = ""
    ) -> Dict[str, Any]:
        """Dispatches the executive HTML assessment report to configured recipients."""
        data = cls.load_data()
        cfg = data.get("email_config", {})
        sender = cfg.get("sender_email", "").strip()
        pwd = cfg.get("sender_password", "")
        host = cfg.get("smtp_host", "smtp.gmail.com").strip()
        port = int(cfg.get("smtp_port", 587))
        use_tls = bool(cfg.get("use_tls", True))

        if not sender or not pwd:
            return {"success": False, "detail": "Email sender address or app password is not configured."}

        to_str = (recipients_override or cfg.get("default_receiver", "")).strip()
        cc_str = (cc_override or cfg.get("default_cc", "")).strip()

        to_list = [r.strip() for r in to_str.split(",") if r.strip()]
        cc_list = [c.strip() for c in cc_str.split(",") if c.strip()] if cc_str else []

        if not to_list:
            to_list = [sender]

        all_recipients = list(set(to_list + cc_list))

        subject = f"📊 [Azure FinSecOps] {schedule_name} - {workspace_name} Report"
        html_content = cls.generate_html_report_email(summary, results, workspace_name, scope, schedule_name)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(to_list)
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)

        msg.attach(MIMEText(html_content, "html"))

        try:
            if port == 465:
                server = smtplib.SMTP_SSL(host, port, timeout=15)
            else:
                server = smtplib.SMTP(host, port, timeout=15)

            server.ehlo()
            if use_tls and port != 465:
                server.starttls()
                server.ehlo()

            server.login(sender, pwd)
            server.sendmail(sender, all_recipients, msg.as_string())
            server.quit()

            logger.info(f"Scheduled report '{schedule_name}' emailed to {all_recipients}")
            return {"success": True, "recipients": all_recipients}
        except Exception as e:
            logger.error(f"Failed to dispatch scheduled email: {e}")
            return {"success": False, "detail": str(e)}

    @classmethod
    def start_background_worker(cls, get_connection_callback):
        """Starts the recurring scheduler background daemon."""
        with cls._lock:
            if cls._worker_started:
                return
            cls._worker_started = True

        def _worker_loop():
            logger.info("Scheduler background daemon started.")
            while True:
                try:
                    time.sleep(30)
                    cls._check_and_run_schedules(get_connection_callback)
                except Exception as e:
                    logger.error(f"Scheduler worker iteration error: {e}")

        t = threading.Thread(target=_worker_loop, daemon=True)
        t.start()

    @classmethod
    def _check_and_run_schedules(cls, get_connection_callback):
        data = cls.load_data()
        schedules = data.get("schedules", [])
        now = datetime.datetime.now()
        modified = False

        for s in schedules:
            if s.get("status") != "Active":
                continue

            next_run_str = s.get("next_run_at")
            if not next_run_str:
                continue

            try:
                next_run = datetime.datetime.fromisoformat(next_run_str)
            except Exception:
                continue

            if now >= next_run:
                logger.info(f"Executing due schedule: [{s.get('id')}] {s.get('name')}")
                conn = get_connection_callback()
                if not conn:
                    s["last_run_at"] = now.isoformat()
                    s["last_run_status"] = "Skipped"
                    s["last_run_message"] = "Skipped: No active Azure connection session found."
                    s["next_run_at"] = cls._calculate_next_run(
                        s.get("frequency", "daily"),
                        s.get("time_of_day", "09:00"),
                        s.get("day_of_week", "Monday"),
                        int(s.get("day_of_month", 1))
                    ).isoformat()
                    modified = True
                    continue

                # Run assessment in synchronous helper
                try:
                    from app.services.scheduler_service import execute_scheduled_assessment
                    summary, results = execute_scheduled_assessment(conn, s.get("scope", "all"))
                    email_res = cls.send_report_email(
                        summary=summary,
                        results=results,
                        workspace_name=conn.get("workspace_name", "Azure Workspace"),
                        scope=s.get("scope", "all"),
                        schedule_name=s.get("name", "Scheduled Assessment"),
                        recipients_override=s.get("recipients", ""),
                        cc_override=s.get("cc", "")
                    )

                    s["last_run_at"] = now.isoformat()
                    if email_res.get("success"):
                        s["last_run_status"] = "Success"
                        s["last_run_message"] = f"Report delivered to {', '.join(email_res.get('recipients', []))}"
                    else:
                        s["last_run_status"] = "Completed with Email Error"
                        s["last_run_message"] = email_res.get("detail", "Email dispatch error.")

                except Exception as ex:
                    logger.error(f"Error running scheduled assessment {s.get('name')}: {ex}")
                    s["last_run_at"] = now.isoformat()
                    s["last_run_status"] = "Failed"
                    s["last_run_message"] = f"Execution error: {str(ex)}"

                s["next_run_at"] = cls._calculate_next_run(
                    s.get("frequency", "daily"),
                    s.get("time_of_day", "09:00"),
                    s.get("day_of_week", "Monday"),
                    int(s.get("day_of_month", 1))
                ).isoformat()
                modified = True

        if modified:
            cls.save_data(data)

def execute_scheduled_assessment(conn: Dict[str, Any], scope: str):
    """Executes the requested assessment modules synchronously for the scheduler daemon."""
    import asyncio
    from app.assessments.registry import assessment_registry
    from app.assessments.base import AssessmentContext
    from app.core.azure_client_factory import azure_client_factory
    from app.intelligence.aggregation import AssessmentAggregator

    if scope == "security":
        target_assessments = assessment_registry.get_security_assessments()
    elif scope == "cost":
        target_assessments = assessment_registry.get_cost_assessments()
    else:
        target_assessments = assessment_registry.get_all_assessments()

    async def _async_run():
        client = await azure_client_factory.get_client_for_session(
            tenant_id=conn["tenant_id"],
            client_id=conn["client_id"],
            client_secret=conn.get("client_secret")
        )
        ctx = AssessmentContext(
            connection_id=conn.get("connection_id", "scheduled-run"),
            workspace_name=conn.get("workspace_name", "Azure Workspace"),
            tenant_id=conn["tenant_id"],
            subscriptions=conn.get("subscriptions", []),
            client=client,
            currency=conn.get("currency", "USD"),
            target_tags=conn.get("target_tags", []),
            prod_tags=conn.get("prod_tags", []),
            test_tags=conn.get("test_tags", []),
            client_id=conn.get("client_id"),
            client_secret=conn.get("client_secret")
        )
        results = {}
        for ass in target_assessments:
            try:
                res = await ass.run(ctx)
                results[ass.assessment_id] = res
            except Exception as e:
                logger.error(f"Scheduled module {ass.code} error: {e}")

        summary = AssessmentAggregator.aggregate_results(results, default_currency=conn.get("currency", "USD"))
        return summary, results

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_async_run())
    finally:
        loop.close()
