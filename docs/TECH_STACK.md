# Azure FinSecOps Platform - Enterprise Technology Stack & Architecture Specification

> **Document Version:** 3.0.0  
> **Target Audience:** Client Technical Leadership, Enterprise Architects, Security & FinOps Steering Committees  
> **Author:** Senior Project Delivery Manager & Principal Solution Architect  
> **Environment:** Hybrid Cloud / Microsoft Azure Enterprise Infrastructure  

---

## 1. Executive Summary & Platform Philosophy

The **Azure FinSecOps Platform** is an enterprise-grade cloud governance and financial optimization system engineered to deliver deep visibility, automated assessment, and verifiable savings across multi-tenant Microsoft Azure estates. 

Built with an **asynchronous-first architecture**, the platform connects directly to Azure native management backbones-including Azure Resource Graph (ARG), Azure Resource Manager (ARM), Microsoft Defender for Cloud, Azure Monitor, and Azure Cost Management-to evaluate infrastructure against 32 proprietary evaluation modules (14 Security Posture modules and 18 Financial Optimization modules).

```mermaid
flowchart TD
    subgraph ClientLayer["Presentation & Interaction Layer (Client-Side)"]
        UI["Modern Vanilla ES6+ SPA\n(Responsive CSS3, FontAwesome 6, Zero-Build)"]
        Store["Browser Session Storage\n(State Persistence across Page Refreshes)"]
    end

    subgraph APILayer["Application Gateway & REST API Layer"]
        FastAPI["FastAPI / Flask ASGI Engine\n(High-Throughput Asynchronous Coroutines)"]
        AuthService["MSAL Token Provider & Session Vault\n(Strict Zero-Disk Secret Handling)"]
        JobManager["Asynchronous Job Evaluation Pipeline\n(Concurrency Throttles & Progress Engine)"]
    end

    subgraph EngineLayer["Core Evaluation & Intelligence Engine"]
        SecRegistry["14 Security Assessment Engines\n(Defender for Cloud, RBAC, Governance)"]
        CostRegistry["18 Cost Optimization Engines\n(Metrics Telemetry, Cost Query, Sizing)"]
        Aggregator["Cross-Tenant Aggregation & Deduplication\n(KPI Synthesis & Currency Formatting)"]
    end

    subgraph ReportLayer["Customer Deliverable Generation Engine"]
        PDFGen["ReportLab PDF Builder\n(Landscape Letter/A4, Boardroom Tables)"]
        ExcelGen["OpenPyXL Workbook Compiler\n(Multi-Tab Spreadsheets, Auto-Fit Layouts)"]
    end

    subgraph AzureCloud["Microsoft Azure Native Management APIs"]
        ARG["Azure Resource Graph (KQL)"]
        ARM["Azure Resource Manager REST APIs"]
        Defender["Microsoft Defender for Cloud APIs"]
        Metrics["Azure Monitor Metrics Telemetry"]
        CostMgmt["Azure Cost Management Query APIs"]
    end

    UI <-->|REST JSON / SSE Polling| APILayer
    UI <--> Store
    APILayer --> EngineLayer
    EngineLayer --> AzureCloud
    EngineLayer --> ReportLayer
    ReportLayer -->|Download Stream| UI
```

---

## 2. Platform Technology Stack Breakdown

| Architectural Tier | Technology / Library | Version | Strategic Business Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime & Language** | Python | 3.11+ | High-concurrency async coroutines, strict typing, and cross-platform reliability. |
| **Web & REST Framework** | FastAPI / Starlette / Flask | 0.110+ | Ultra-low latency asynchronous API endpoints, dependency injection, OpenAPI documentation. |
| **Autonomous AI Gateway** | Google Cloud Vertex AI | v1 | Autonomous multi-step tool calling via `VertexAIInferenceProvider` (`gemini-2.5-flash` / `gemini-2.5-pro`) using `VERTEX_AI_API_KEY`. |
| **Agent Tool Execution** | Dynamic Tool Calling Engine | 15 Tools | 12 domain-specific tools + 3 dynamic runtime tools (`dynamic_code_interpreter`, `azure_generic_resource_query`, `azure_rest_call`). |
| **Authentication & IAM** | MSAL Python (`msal`) | 1.28+ | Microsoft identity platform OAuth2 Client Credentials flow; acquires ARM tokens without secret exposure. |
| **HTTP Transport Engine** | HTTPX (`httpx`) | 0.27+ | Asynchronous HTTP client with connection pooling, retries, and timeout management for Azure endpoints. |
| **Data Validation & Schemas** | Pydantic v2 & Pydantic-Settings | 2.6+ | Type-safe schema validation for cloud payloads, job state models, and environment settings. |
| **PDF Reporting Engine** | ReportLab | 4.1+ | Generates vector-grade, landscape boardroom PDF deliverables with custom tables and typography. |
| **Spreadsheet Engine** | OpenPyXL | 3.1+ | Generates formatted Excel deliverables with frozen headers, currency styling, and auto-sized columns. |
| **Frontend Framework** | Pure Vanilla JavaScript (ES6+) | Modern | Zero-build single-page architecture eliminating node_modules vulnerabilities and bundle compilation overhead. |
| **Styling & Design System** | Custom CSS3 + FontAwesome 6 | 6.5.1 | Custom design system with dark/light visual contrast, responsive grids, and font-based iconography. |
| **Configuration Engine** | Python Dotenv (`python-dotenv`) | 1.0+ | Production configuration via `.env` files with runtime fallback defaults. |
| **Authentication & IAM** | MSAL Python (`msal`) | 1.28+ | Microsoft identity platform OAuth2 Client Credentials flow; acquires ARM tokens without secret exposure. |
| **HTTP Transport Engine** | HTTPX (`httpx`) | 0.27+ | Asynchronous HTTP client with connection pooling, retries, and timeout management for Azure endpoints. |
| **Data Validation & Schemas** | Pydantic v2 & Pydantic-Settings | 2.6+ | Type-safe schema validation for cloud payloads, job state models, and environment settings. |
| **PDF Reporting Engine** | ReportLab | 4.1+ | Generates vector-grade, landscape boardroom PDF deliverables with custom tables and typography. |
| **Spreadsheet Engine** | OpenPyXL | 3.1+ | Generates formatted Excel deliverables with frozen headers, currency styling, and auto-sized columns. |
| **Frontend Framework** | Pure Vanilla JavaScript (ES6+) | Modern | Zero-build single-page architecture eliminating node_modules vulnerabilities and bundle compilation overhead. |
| **Styling & Design System** | Custom CSS3 + FontAwesome 6 | 6.5.1 | Custom design system with dark/light visual contrast, responsive grids, and font-based iconography. |
| **Configuration Engine** | Python Dotenv (`python-dotenv`) | 1.0+ | Production configuration via `.env` files with runtime fallback defaults. |

---

## 3. Deep Dive into Architectural Components

### 3.1 Asynchronous Backend & REST API Framework
* **FastAPI with ASGI Architecture (`uvicorn`):** Handles concurrent assessment queries across multiple subscriptions without blocking I/O threads.
* **Non-Blocking Network Layer (`httpx.AsyncClient`):** Communicates with Azure REST APIs over persistent HTTP/2 and HTTP/1.1 connections with TLS 1.3 encryption.
* **Fault-Tolerant Retry Matrix:** Built-in exponential backoff handles Azure ARM 429 (`TooManyRequests`) and transient 503 gateway drops.

```python
# Real Implementation Pattern: Scalable Azure Query Ingestion
async with httpx.AsyncClient(timeout=settings.azure_request_timeout_seconds) as client:
    response = await client.post(
        "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
        headers={"Authorization": f"Bearer {token}"},
        json={"subscriptions": subscription_ids, "query": kql_query}
    )
```

### 3.2 Enterprise Azure Authentication & Security Vault
* **Microsoft Authentication Library (MSAL):** Implements OAuth 2.0 Confidential Client token acquisition targeting `https://management.azure.com/.default`.
* **Zero-Disk Secret Lifecycle:** Client secrets exist strictly in memory within transient task scopes; secrets are never serialized into logs, session stores, or client responses.
* **Granular Least-Privilege Support:** Functions cleanly under Azure built-in roles (`Reader`, `Cost Management Reader`, `Security Reader`).

### 3.3 Dynamic Reporting & Deliverable Generation Engine
The platform exports governance deliverables in two formats:
1. **Executive Landscape PDF (`ReportLab`):**
   - Engineered in landscape Letter format (792 pt $\times$ 612 pt) with precise 20 pt margins, giving 752 pt of usable width.
   - Flowable table layouts wrap long Azure resource IDs and resource group names cleanly.
   - Alternating row styling with primary color branding (`#4F46E5` Indigo for Security, `#EA580C` Rust Orange for Cost).
   - Dynamic currency symbols (`$`, `€`, `£`, `₹`, `A$`, `C$`) matching the tenant's billing profile.

2. **Multi-Tab Spreadsheet Deliverable (`OpenPyXL`):**
   - Separate worksheets for each individual assessment module containing all findings.
   - Executive Summary sheet with automated formula links.
   - Column dimensions auto-fitted based on cell string lengths.
   - Formatted numbers, currency columns, and severity-colored status flags.

### 3.4 Client-Side Single Page Application (SPA)
* **Zero-Build, Pure Standards Approach:** Native ES6+, HTML5, and CSS3 without npm/webpack build tools.
* **Persistent Tab & State Session (`sessionStorage`):** Refreshing the browser or navigating between tabs preserves tenant connection state, running job IDs, findings, and active tab selection.
* **Execution Safety Lockout:** During assessment execution, all execution triggers (`Run All`, `Run Security`, `Run Cost`, and card-level module buttons) are disabled via `.btn-disabled` (`pointer-events: none`).

### 3.5 Enterprise Agentic AI Engine & Dynamic Tool Calling
* **Google Cloud Vertex AI Gateway:** Dedicated `VertexAIInferenceProvider` calling the Vertex AI `generateContent` API (`VERTEX_AI_API_KEY`) with native `functionDeclarations` and `functionResponse` handling.
* **Autonomous Multi-Step Tool Calling Loop:** Agents autonomously inspect requests, select tools, analyze intermediate Azure responses, and iterate through up to `AI_MAX_TOOL_CALLS` (default 10) tool executions before producing executive answers.
* **15 Enterprise Agent Tools:**
  - **12 Domain-Specific Tools:** Specialized assessment evaluators for Secure Score, Defender alerts, VM rightsizing, orphaned disks, unattached public IPs, SQL database metrics, diagnostic logs, and cost spikes.
  - **3 Dynamic Runtime Tools:**
    1. `dynamic_code_interpreter`: Executes sandboxed Python code to calculate complex cost differentials, amortized statistics, and mathematical trends.
    2. `azure_generic_resource_query`: Executes arbitrary KQL queries against Azure Resource Graph to investigate unforeseen or custom cloud configurations.
    3. `azure_rest_call`: Queries any read-only Azure REST API endpoint dynamically with zero hardcoding.
* **Strict Read-Only Guardrails:** Enforces GET-only methods, blocks destructive verbs (`DELETE`, `PATCH`, `PUT`), and redacts bearer tokens, client secrets, and passwords before AI prompt ingestion.

---

## 4. Hardware & Deployment Recommendations

### 4.1 Container & GCP Cloud Run Deployment
* **Container Runtime:** Docker Engine 24+, Podman, or **Google Cloud Run** (see `GCP_CLOUD_RUN_DEPLOYMENT_GUIDE.md`).
* **Base Image:** `python:3.11-slim-bookworm` (minimal footprint, hardened against common CVEs).
* **Compute Footprint:**
  - Minimum: 1 vCPU, 1 GB RAM (evaluates up to 5 subscriptions).
  - Recommended Enterprise: 2 vCPUs, 2–4 GB RAM (evaluates 50+ subscriptions concurrently).
* **Networking:** Outbound HTTPS (`TCP 443`) to:
  - `login.microsoftonline.com` (Azure AD token issuance)
  - `management.azure.com` (ARM, Resource Graph, Monitor, Defender, Cost Management)
  - `prices.azure.com` (Azure Retail Prices API)
  - `aiplatform.googleapis.com` (Google Cloud Vertex AI)

---

## 5. Security & Compliance Safeguards

1. **Read-Only Inspection Guarantee:** The platform executes solely `GET` and read-only `POST` query operations. It contains no destructive API methods.
2. **Data Minimization:** No client customer payload data is inspected. Telemetry is limited to metadata (resource names, SKUs, performance metrics, and cost entries).
3. **Session Encapsulation:** In-memory job stores purge finished executions automatically after their configured TTL.
