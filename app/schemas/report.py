from typing import Optional
from pydantic import BaseModel

class ReportMetadata(BaseModel):
    report_id: str
    report_type: str # security_pdf, security_excel, cost_pdf, cost_excel
    file_name: str
    file_size_bytes: int
    created_at: str
    expires_at: str
    download_url: str

class ReportDownloadInfo(BaseModel):
    report_id: str
    file_name: str
    content_type: str
